package examples.local;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

// Same annotation names, but not Spring annotations.
@Retention(RetentionPolicy.RUNTIME)
@interface RestController {}
@Retention(RetentionPolicy.RUNTIME)
@interface GetMapping { String value(); }

@RestController
public class LocalController {
    @GetMapping("/fake")
    public String search(String command) {
        return command;
    }
}
