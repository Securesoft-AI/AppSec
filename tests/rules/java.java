import java.io.*;
import java.net.URL;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.sql.*;
import javax.crypto.Cipher;
import javax.net.ssl.*;
import javax.servlet.http.HttpServletRequest;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.web.bind.annotation.*;

@RestController
public class Demo {

    public void sql(Connection conn, HttpServletRequest request) throws Exception {
        String id = request.getParameter("id");
        Statement st = conn.createStatement();
        // ruleid: java-sql-injection
        st.executeQuery("SELECT * FROM users WHERE id = " + id);
        // ok: java-sql-injection
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, id);
        ps.executeQuery();
    }

    public void cmd(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        // ruleid: java-command-injection
        Runtime.getRuntime().exec("ping -c 1 " + host);
        // ok: java-command-injection
        Runtime.getRuntime().exec("uptime");
    }

    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) throws Exception {
        // ruleid: java-ssrf
        return new URL(url).openStream().toString();
    }

    @GetMapping("/file")
    public void file(@RequestParam String name) throws Exception {
        // ruleid: java-path-traversal
        new FileInputStream("/srv/data/" + name);
        // ok: java-path-traversal
        new FileInputStream("/srv/data/static.txt");
    }

    public Object deser(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        // ruleid: java-insecure-deserialization
        return ois.readObject();
    }

    public void xml() throws Exception {
        // ruleid: java-xxe
        DocumentBuilderFactory bad = DocumentBuilderFactory.newInstance();
        bad.newDocumentBuilder();

        // ok: java-xxe
        DocumentBuilderFactory good = DocumentBuilderFactory.newInstance();
        good.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        good.newDocumentBuilder();
    }

    public void crypto() throws Exception {
        // ruleid: java-weak-crypto
        Cipher.getInstance("DES");
        // ruleid: java-weak-crypto
        MessageDigest.getInstance("MD5");
        // ok: java-weak-crypto
        Cipher.getInstance("AES/GCM/NoPadding");
    }

    static class TrustAll implements X509TrustManager {
        public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) { }
        // ruleid: java-tls-trust-all
        public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) { }
        public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
    }
}
