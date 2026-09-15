package examples.servlet;

// Neither HttpServlet inheritance nor servlet registration.
public class LocalHandler {
    public String doPost(String request) {
        return request;
    }

    public String getParameter(String name) {
        return "constant";
    }
}
