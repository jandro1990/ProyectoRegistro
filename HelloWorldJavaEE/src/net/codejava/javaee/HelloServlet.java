package net.codejava.javaee;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.codejava.javaee.Hasher2;

/**
 * Servlet implementation class HelloServlet
 */
@WebServlet("/helloServlet")
public class HelloServlet extends HttpServlet {
	
	
	public String driver = "com.mysql.jdbc.Driver";

    // Nombre de la base de datos
    public String database = "simple_shiro_web_app";

    // Host
    public String hostname = "127.0.0.1";

    // Puerto
    public String port = "3307";

    // Ruta de nuestra base de datos (desactivamos el uso de SSL con "?useSSL=false")
    public String url = "jdbc:mysql://" + hostname + ":" + port + "/" + database + "?useSSL=false&useUnicode=true&useJDBCCompliantTimezoneShift=true&useLegacyDatetimeCode=false&serverTimezone=UTC";

    // Nombre de usuario
    public String username = "root";

    // Clave de usuario
    public String password = "";

   
       

    /**
     * @see HttpServlet#HttpServlet()
     */
    public HelloServlet() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		 Connection conn = null;

	        try {
	            Class.forName(driver);
	            
	            conn = DriverManager.getConnection(url, username, password);
	        } catch (ClassNotFoundException | SQLException e) {
	            e.printStackTrace();
	        }
	    //private static final long serialVersionUID = 1L;
		
		String user = request.getParameter("user");
		String password = request.getParameter("password");
		String p = Hasher2.readPassword(password);
		PrintWriter writer = response.getWriter();
		writer.println("<h1>Your user is " + user + "</h1>");
		writer.println("<h1>Your password is " + password + "</h1>");
		writer.println("<h1>Your password is " + p + "</h1>");
		writer.close();
		// TODO Auto-generated method stub
		
		 String sSQL =   "";
		 sSQL =  "INSERT INTO USERS (username, password) VALUES ('"+user+"','"+p+"')";
		 try {
			PreparedStatement pstm = conn.prepareStatement(sSQL);
			pstm.executeUpdate();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		 
	}

}
