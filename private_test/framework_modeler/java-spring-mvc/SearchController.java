package examples.spring;

import java.io.IOException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// Intentionally unsafe: static-analysis fixture, not production code.
@RestController
public class SearchController {
    @GetMapping("/search")
    public String search(@RequestParam("cmd") String command) throws IOException {
        execute(command);
        return "queued";
    }

    private void execute(String command) throws IOException {
        Runtime.getRuntime().exec(command);
    }

    // Public method alone does not make an HTTP endpoint.
    public String preview(String command) {
        return command;
    }
}
