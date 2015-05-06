package iica.authentication;

import java.sql.SQLException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.dspace.authenticate.AuthenticationManager;
import org.dspace.authenticate.AuthenticationMethod;
import org.dspace.authorize.AuthorizeException;
import org.dspace.core.Context;
import org.dspace.eperson.EPerson;


//Propios para proyecto de Google
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.google.common.collect.ImmutableMap;

/**
 * @author Randall Vargas
 * @version $Revision$
 */
public class GPlusAuthentication implements AuthenticationMethod {

    private static Logger log = Logger.getLogger(GPlusAuthentication.class);//Bitacora de status

    private final String clientID = "994939257755-s7j1j8qimlnok6fl2kumd7e7porttv9a.apps.googleusercontent.com";
    private final String clientSecret = "gkzOj0K5-pFgvqydLzmIZALw";
    private final String redirectURL = "/gplus-login";

    public boolean canSelfRegister(Context context,
                                   HttpServletRequest request,
                                   String email)
            throws SQLException
    {
        return false;
    }

    public void initEPerson(Context context,
                            HttpServletRequest request,
                            EPerson eperson)
            throws SQLException
    {
        //No implementado, no se requiere
    }

    public boolean allowSetPassword(Context context,
                                    HttpServletRequest request,
                                    String username)
            throws SQLException
    {
        return false;//No se permite cambio de clave
    }

    public boolean isImplicit(){
        return true;
    }

    public int[] getSpecialGroups(Context context, HttpServletRequest request)
    {
        return new int[0];
    }

    public int authenticate(Context context,
                            String username,
                            String password,
                            String realm,
                            HttpServletRequest request)
            throws SQLException
    {
        String code = request.getParameter("code");

        if(code == null){//Usuario no se autentica o no da consentimiento a la aplicacion

            HttpClient cliente = new DefaultHttpClient();

            /*try{
                cliente.execute(new HttpPost(FormarSignInURL()));
            }catch (IOException e){
                log.error("Error realizando el post de Sign In a Google.");
            }*/

        }else{

            JSONObject usuario = null;

            try{
                usuario = ObtenerInfoUsuario(request);
            }catch (Exception e){
                return BAD_CREDENTIALS;
            }

            String email = (String) usuario.get("email");
            String nombre = (String) usuario.get("given_name");
            String apellido = (String) usuario.get("family_name");

            EPerson ePerson = null;

            try{
                ePerson = EPerson.findByEmail(context, email);

                if(ePerson == null){
                    RegistrarEPerson(context, request, email, nombre, apellido);
                }

                context.setCurrentUser(ePerson);
                AuthenticationManager.initEPerson(context, request, ePerson);

                return SUCCESS;

            }catch (AuthorizeException e){
                log.trace("Failed to authorize looking up EPerson", e);
            }

        }

        return NO_SUCH_USER;
    }

    public String loginPageURL(Context context,
                               HttpServletRequest request,
                               HttpServletResponse response)
    {
        return FormarSignInURL(request);
    }

    public String loginPageTitle(Context context)

    {
        return "Login con Google";
    }

    //Otras clases para Login de Google.

    private String FormarSignInURL(HttpServletRequest request)
    {

        StringBuilder url = new StringBuilder();

        url.append("https://accounts.google.com/o/oauth2/auth");//URL base de autenticacion
        url.append("?client_id=" + clientID);//ID del cliente (Consola de Desarrolladores)
        url.append("&redirect_uri="+ request.getContextPath()+redirectURL);//Url de retorno desde Google
        url.append("&scope=https://www.googleapis.com/auth/userinfo#email");//Tipo de autorizacion que va a dar Google
        url.append("&response_type=code&state=oauth20dspace");//Tipo de Respuesta codigo, estado para garantizar que vuelvo de google.

        return url.toString();
    }

    private JSONObject ObtenerInfoUsuario(HttpServletRequest request) throws ServletException, IOException
    {

        JSONObject retorno = null;

        if(request.getParameter("error")  != null){

            log.error("Google retorna un error");

        }else{

            String code = request.getParameter("code");

            String post = Ejecutar_POST("https://accounts.google.com/o/oauth2/token", ImmutableMap.<String, String>builder()
                          .put("code", code)
                          .put("client_id", clientID)
                          .put("client_secret", clientSecret)
                          .put("redirect_uri", redirectURL)
                          .put("grant_type", "authorization_code").build());

            JSONObject jsonObject = null;

            try{
                jsonObject = Parsear_JSON(post);
            }catch (ParseException e){
                throw new RuntimeException("No se puede parsear el JSON retornado por Google");
            }

            String usuarioJSON = Ejecutar_GET("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + ((String) jsonObject.get("access_token")));

            try{
                retorno = Parsear_JSON(usuarioJSON);
            }catch (ParseException e){
                throw new RuntimeException("No se puede parsear el JSON retornado por Google");
            }

        }

        return retorno;

    }

    private JSONObject Parsear_JSON(String json) throws ParseException
    {
        JSONObject jsonObject = (JSONObject) new JSONParser().parse(json);

        return jsonObject;
    }

    private String Ejecutar_GET(String url) throws ClientProtocolException, IOException
    {
        return Ejecutar_Request(new HttpGet(url));
    }

    private String Ejecutar_POST(String url, Map<String,String> parametros) throws ClientProtocolException, IOException
    {
        HttpPost request = new HttpPost(url);

        List<NameValuePair> nvps = new ArrayList<NameValuePair>();

        for(String key : parametros.keySet()){
            nvps.add(new BasicNameValuePair(key, parametros.get(key)));
        }

        request.setEntity(new UrlEncodedFormEntity(nvps));

        return Ejecutar_Request(request);
    }

    private String Ejecutar_Request(HttpRequestBase request) throws ClientProtocolException, IOException
    {
        HttpClient cliente = new DefaultHttpClient();
        HttpResponse response = cliente.execute(request);

        HttpEntity entity = response.getEntity();
        String body = EntityUtils.toString(entity);

        if(response.getStatusLine().getStatusCode() != 200){
            throw new RuntimeException("Expected 200 but got "+response.getStatusLine().getStatusCode() + " with body: " +body);
        }else{
            return body;
        }
    }

    private EPerson RegistrarEPerson(Context context, HttpServletRequest request, String email, String nombre, String apellido) throws SQLException, AuthorizeException
    {
        context.turnOffAuthorisationSystem();
        EPerson ePerson = EPerson.create(context);

        ePerson.setEmail(email);
        ePerson.setFirstName(nombre);
        ePerson.setLastName(apellido);
        ePerson.setCanLogIn(true);

        AuthenticationManager.initEPerson(context, request, ePerson);
        ePerson.update();
        context.commit();

        context.restoreAuthSystemState();

        return ePerson;

    }

    /*class SignInServlet extends HttpServlet{
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
        {
            //Redirecciono a Google para autorizacion
            StringBuilder url = new StringBuilder();

            url.append("https://accounts.google.com/o/oauth2/auth");//URL base de autenticacion
            url.append("?client_id=" + clientID);//ID del cliente (Consola de Desarrolladores)
            url.append("&redirect_uri="+redirectURL);//Url de retorno desde Google
            url.append("&scope=https://www.googleapis.com/auth/userinfo#email");//Tipo de autorizacion que va a dar Google
            url.append("&response_type=code&state=oauth20dspace");//Tipo de Respuesta codigo, estado para garantizar que vuelvo de google.

            response.sendRedirect(url.toString());//Redirecciono a Google
        }

    }

    class CallbackServer extends HttpServlet{
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
        {
            if(request.getParameter("error") != null){
                log.error("Google retorna error");
                return;
            }else{

                String code = request.getParameter("code");

                String post = Ejecutar_POST("https://accounts.google.com/o/oauth2/token", ImmutableMap.<String, String>builder()
                .put("code", code)
                .put("client_id", clientID)
                .put("client_secret", clientSecret)
                .put("redirect_uri", redirectURL)
                .put("grant_type", "authorization_code").build());

                JSONObject jsonObject = null;

                try{
                    jsonObject = Parsear_JSON(post);
                }catch (ParseException e){
                    throw new RuntimeException("No se puede parsear el JSON retornado por Google");
                }

                String usuarioJSON = Ejecutar_GET("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + ((String) jsonObject.get("access_token")));

                JSONObject usuario = null;

                try{
                    usuario = Parsear_JSON(usuarioJSON);
                }catch (ParseException e){
                    throw new RuntimeException("No se puede parsear el JSON retornado por Google");
                }
            }
        }
    }*/

}


