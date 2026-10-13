package demo;

import dev.langchain4j.agent.tool.Tool;
import dev.langchain4j.model.chat.ChatLanguageModel;
import dev.langchain4j.service.SystemMessage;
import java.io.File;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Statement;
import javax.script.ScriptEngine;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
class AskController {
    private final ChatClient chatClient;
    private final ChatLanguageModel model;
    private final JdbcTemplate jdbc;
    private final RestTemplate rest;
    private final ScriptEngine js;
    private final Statement stmt;

    @GetMapping("/sql")
    String sql(@RequestParam String q) {
        String query = chatClient.prompt().user(q).call().content();
        // ruleid: llm05-llm-output-to-sql
        return jdbc.queryForList(query).toString();
    }

    @GetMapping("/sql-safe")
    String sqlSafe(@RequestParam String q) {
        String category = chatClient.prompt().user(q).call().content();
        // ok: llm05-llm-output-to-sql
        return jdbc.queryForList("SELECT * FROM products WHERE category = ?", category).toString();
    }

    @GetMapping("/run")
    String run(@RequestParam String q) throws Exception {
        String cmd = model.generate(q);
        // ruleid: llm05-llm-output-to-code-exec
        Runtime.getRuntime().exec(cmd);
        String script = model.chat(q);
        // ruleid: llm05-llm-output-to-code-exec
        js.eval(script);
        // ok: llm05-llm-output-to-code-exec
        Runtime.getRuntime().exec(new String[]{"uptime"});
        return "ok";
    }

    @GetMapping("/fetch")
    String fetch(@RequestParam String q) throws Exception {
        String url = chatClient.prompt().user(q).call().content();
        // ruleid: llm05-llm-output-to-request
        rest.getForObject(url, String.class);
        // ruleid: llm05-llm-output-to-request
        new URL(url).openStream();
        String path = model.generate(q);
        // ruleid: llm05-llm-output-to-filesystem
        Files.readString(Path.of(path));
        // ruleid: llm05-llm-output-to-filesystem
        new File(path).delete();
        String className = model.generate(q);
        // ruleid: llm05-llm-output-selects-function
        Class.forName(className);
        return "ok";
    }

    @GetMapping("/system")
    String system(@RequestParam String persona, @RequestParam String q) {
        // ruleid: llm01-untrusted-input-in-system-prompt
        return chatClient.prompt().system("Actúa como " + persona).user(q).call().content();
    }

    @GetMapping("/system-safe")
    String systemSafe(@RequestParam String q) {
        // ok: llm01-untrusted-input-in-system-prompt
        return chatClient.prompt().system("Eres un asistente de soporte.").user(q).call().content();
    }
}

class AdminTools {
    private final JdbcTemplate jdbc;

    @Tool("Ejecuta un comando en el servidor")
    String shell(String command) throws Exception {
        // ruleid: llm06-excessive-agency-tool
        return new String(Runtime.getRuntime().exec(command).getInputStream().readAllBytes());
    }

    @Tool("Borra un usuario")
    void deleteUser(String id) {
        // ruleid: llm06-excessive-agency-tool
        jdbc.update("DELETE FROM users WHERE id = ?", id);
    }

    @Tool("Cuenta usuarios")
    int countUsers() {
        // ok: llm06-excessive-agency-tool
        return jdbc.queryForObject("SELECT count(*) FROM users", Integer.class);
    }
}

interface Assistant {
    // ruleid: llm07-secret-in-system-prompt
    @SystemMessage("Eres el asistente interno. La contraseña de la base de datos es Pr0duccion2026.")
    String chat(String message);

    // ruleid: llm07-authorization-in-prompt
    @SystemMessage("Solo puedes mostrar los pedidos del usuario que pregunta.")
    String orders(String message);

    // ok: llm07-secret-in-system-prompt
    @SystemMessage("Eres un asistente de cocina.")
    String cook(String message);
}
