"""Facturación con Stripe (RF-4.5): Checkout, Portal de cliente y webhooks.

Se usa la API REST de Stripe con httpx (ya es dependencia del servicio) en lugar de su SDK: son tres
llamadas. Los webhooks se verifican con la firma de Stripe (HMAC-SHA256 con tolerancia de 5 minutos).

El plan de cada instalación lo deciden los eventos de suscripción, no la vuelta del Checkout: así un
usuario no puede activarse un plan visitando la URL de éxito.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from appsec_ai.service.db import Installation

API = "https://api.stripe.com/v1"
TOLERANCE_SECONDS = 300


class BillingError(RuntimeError):
    pass


class Stripe:
    def __init__(self, secret_key: str, transport: httpx.BaseTransport | None = None):
        self.http = httpx.Client(base_url=API, timeout=20, transport=transport,
                                 headers={"Authorization": f"Bearer {secret_key}"})

    def _post(self, path: str, data: dict) -> dict:
        r = self.http.post(path, data=data)
        if r.status_code >= 400:
            # El cuerpo de error de Stripe no contiene la clave; las cabeceras sí, y no se registran.
            raise BillingError(f"Stripe {path} -> {r.status_code}: {r.text[:300]}")
        return r.json()

    def checkout_url(self, price_ids: list[str], installation_id: int, customer_id: str, success_url: str,
                     cancel_url: str) -> str:
        data = {
            "mode": "subscription",
            "client_reference_id": str(installation_id), "metadata[installation_id]": str(installation_id),
            "subscription_data[metadata][installation_id]": str(installation_id),
            "success_url": success_url, "cancel_url": cancel_url, "allow_promotion_codes": "true",
        }
        for i, price in enumerate(price_ids):
            data[f"line_items[{i}][price]"], data[f"line_items[{i}][quantity]"] = price, "1"
        if customer_id:
            data["customer"] = customer_id
        return self._post("/checkout/sessions", data)["url"]

    def portal_url(self, customer_id: str, return_url: str) -> str:
        return self._post("/billing_portal/sessions", {"customer": customer_id, "return_url": return_url})["url"]


def verify_event(payload: bytes, signature_header: str, secret: str, now: float | None = None) -> dict:
    """Comprueba la cabecera Stripe-Signature (t=...,v1=...) y devuelve el evento."""
    if not secret or not signature_header:
        raise BillingError("firma ausente")
    parts = [p.split("=", 1) for p in signature_header.split(",") if "=" in p]
    timestamp = next((v for k, v in parts if k == "t"), "")
    signatures = [v for k, v in parts if k == "v1"]
    if not timestamp.isdigit() or not signatures:
        raise BillingError("firma mal formada")
    if abs((now or time.time()) - int(timestamp)) > TOLERANCE_SECONDS:
        raise BillingError("firma caducada")
    expected = hmac.new(secret.encode(), timestamp.encode() + b"." + payload, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, s) for s in signatures):
        raise BillingError("firma no válida")
    return json.loads(payload)


def apply_event(s: Session, event: dict, price_to_item: dict[str, str]) -> dict:
    """Aplica un evento de Stripe a la instalación correspondiente. Idempotente y tolerante al desorden."""
    kind, obj, created = event.get("type", ""), event.get("data", {}).get("object", {}), int(event.get("created", 0))
    if kind == "checkout.session.completed":
        inst = _installation(s, obj.get("client_reference_id") or (obj.get("metadata") or {}).get("installation_id"),
                             obj.get("customer"))
        if inst is None:
            return {"ignored": "instalación desconocida"}
        inst.stripe_customer_id = obj.get("customer") or inst.stripe_customer_id
        inst.stripe_subscription_id = obj.get("subscription") or inst.stripe_subscription_id
        return {"installation": inst.id, "linked": True}
    if kind in ("customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted"):
        inst = _installation(s, (obj.get("metadata") or {}).get("installation_id"), obj.get("customer"))
        if inst is None:
            return {"ignored": "instalación desconocida"}
        if created and created < (inst.billing_event_at or 0):
            return {"ignored": "evento antiguo"}  # Stripe no garantiza el orden de entrega
        items = (obj.get("items") or {}).get("data") or []
        prices = [(item.get("price") or {}).get("id", "") for item in items]
        deleted = kind.endswith(".deleted")
        inst.stripe_customer_id = obj.get("customer") or inst.stripe_customer_id
        inst.stripe_subscription_id = obj.get("id", inst.stripe_subscription_id)
        inst.subscription_status = "canceled" if deleted else obj.get("status", "")
        # Servicios y paquetes contratados: cada precio de la suscripción es uno de ellos.
        inst.modules = [] if deleted else sorted({price_to_item[p] for p in prices if p in price_to_item})
        inst.plan = "paid" if inst.modules else "free"
        inst.billing_event_at = created
        return {"installation": inst.id, "modules": inst.modules, "status": inst.subscription_status}
    return {"ignored": kind}


def _installation(s: Session, installation_id, customer_id) -> Installation | None:
    if installation_id and str(installation_id).isdigit():
        inst = s.get(Installation, int(installation_id))
        if inst is not None:
            return inst
    if customer_id:
        return s.scalars(select(Installation).where(Installation.stripe_customer_id == customer_id)).first()
    return None
