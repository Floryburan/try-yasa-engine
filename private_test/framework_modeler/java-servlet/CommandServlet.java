package examples.servlet;

import java.io.IOException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// Intentionally unsafe: static-analysis fixture, not production code.
@WebServlet("/command")
public class CommandServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String command = request.getParameter("cmd");
        execute(command);
        response.getWriter().write("queued");
    }

    private void execute(String command) throws IOException {
        Runtime.getRuntime().exec(command);
    }
}
