package org.dspace.app.webui.servlet;

import java.io.IOException;
import java.sql.SQLException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import org.dspace.app.webui.util.Authenticate;
import org.dspace.app.webui.util.JSPManager;
import org.dspace.authorize.AuthorizeException;
import org.dspace.core.Context;
import org.dspace.authenticate.AuthenticationManager;
import org.dspace.authenticate.AuthenticationMethod;

/**
 * Created by rvargas on 5/6/15.
 */
public class GPlusServlet extends DSpaceServlet{

    private static Logger log = Logger.getLogger(DSpaceServlet.class);


    /*Método que se invoca cuando el Servlet es invocado
    * desde la dirección domain.dom/gplus-login
    * (Ver path: dspace-jspui/src/main/webapp/WEB-INF/web.xml)
    * Éste método es el que invoca los métodos POST y GET
    * que se ejecutan posterior a que el usuario es
    * redireccionado a la página de Google y proporciona
    * su Usuario y Contraseña.
    */
    protected void doDSGet(Context context,
                           HttpServletRequest request,
                           HttpServletResponse response)
            throws ServletException, IOException, SQLException, AuthorizeException
    {
        int status = AuthenticationManager.authenticate(context, null, null, null, request);

        String error = null;

        log.info("Authentication returned " + status);

        if(status == AuthenticationMethod.SUCCESS){
            try {
                context.commit();
            }catch (SQLException ex){

                log.error("Failed to write an updated last_active field of an "
                        + "EPerson into the databse.", ex);

            }

            Authenticate.loggedIn(context, request, context.getCurrentUser());

            log.info("Authentication Successful");

            Authenticate.resumeInterruptedRequest(request, response);

            return;
        }else if (status == AuthenticationMethod.CERT_REQUIRED){
            error = "/error/require-certificate.jsp";
        }else if(status == AuthenticationMethod.NO_SUCH_USER){
            error = "/login/no-single-sign-out.jsp";
        }else if(status == AuthenticationMethod.BAD_ARGS){
            error = "/login/no-email.jsp";
        }

        log.info("Authentication Error");
        JSPManager.showJSP(request, response, error);
        return;
    }

}
