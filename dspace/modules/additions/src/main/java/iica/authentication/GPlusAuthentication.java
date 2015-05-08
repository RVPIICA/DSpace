package iica.authentication;

import java.sql.SQLException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.dspace.authenticate.AuthenticationManager;
import org.dspace.authenticate.AuthenticationMethod;
import org.dspace.authorize.AuthorizeException;
import org.dspace.core.ConfigurationManager;
import org.dspace.core.Context;
import org.dspace.eperson.EPerson;


//Propios para proyecto de Google Plus
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
 * @author Randall Vargas Padilla
 * @version $Revision$
 */
public class GPlusAuthentication implements AuthenticationMethod {


    private final String redirectURL = "/gplus-login";//Nombre del path donde se mapea el servlet de procesamiento

    private static Logger log = Logger.getLogger(GPlusAuthentication.class);//Bitacora de status

    /** Obtengo los datos de configuración que requiero**/
    private String clientID = ConfigurationManager.getProperty("authentication-gplus", "client_id");
    private String clientSecret = ConfigurationManager.getProperty("authentication-gplus", "client_secret");
    private String appDomain = ConfigurationManager.getProperty("authentication-gplus", "domain");

    /*No lo requiero*/
    public boolean canSelfRegister(Context context,
                                   HttpServletRequest request,
                                   String email)
            throws SQLException
    {
        return false;
    }
    /* No lo requiero */
    public void initEPerson(Context context,
                            HttpServletRequest request,
                            EPerson eperson)
            throws SQLException
    {
        //No implementado, no se requiere
    }
    /* No almaceno Password en DSpace */
    public boolean allowSetPassword(Context context,
                                    HttpServletRequest request,
                                    String username)
            throws SQLException
    {
        return false;//No se permite cambio de clave
    }
    /* La autenticación no tiene un formulario dentro de DSpace*/
    public boolean isImplicit(){
        return true;
    }
    /*No implementado */
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

        if(code == null){//Usuario no se autentica o no da consentimiento a la aplicacion en goolge

            log.info("GPlus User didn't consent application");
            return CERT_REQUIRED;

        }else{

            log.info("GPLUS Attempting to authenticate JSON User and get it's information");

            JSONObject usuario = null;

            try{
                usuario = ObtenerInfoUsuario(request);
            }catch (Exception e){
                log.error(e.getMessage());
                return BAD_CREDENTIALS;
            }

            String email = (String) usuario.get("email");
            String nombre = (String) usuario.get("given_name");
            String apellido = (String) usuario.get("family_name");

            log.info("GPLUS Managed to get User data");

            EPerson ePerson = null;

            try{
                log.info("GPLUS Trying to find EPerson by Email");
                ePerson = EPerson.findByEmail(context, email);

                if(ePerson == null){
                    log.info("GPLUS EPerson not found, trying to register into system");
                    ePerson = RegistrarEPerson(context, request, email, nombre, apellido);
                }

                log.info("GPlus Logging in EPerson");

                context.setCurrentUser(ePerson);
                AuthenticationManager.initEPerson(context, request, ePerson);

                log.info("GPlus Login Succes");

                return SUCCESS;

            }catch (AuthorizeException e){
                log.trace("GPLUS Failed to authorize looking up EPerson", e);
                return CERT_REQUIRED;
            }

        }
    }

    public String loginPageURL(Context context,
                               HttpServletRequest request,
                               HttpServletResponse response)
    {
        return FormarSignInURL(request);//Realizo POST inicial a Google para dialogo de autenticación.
    }

    public String loginPageTitle(Context context)

    {
        return "Google Authentication";
    }

    //Otras clases para Login de Google.

    private String FormarSignInURL(HttpServletRequest request)
    {

        StringBuilder url = new StringBuilder();

        url.append("https://accounts.google.com/o/oauth2/auth");//URL base de autenticacion
        url.append("?redirect_uri="+ appDomain + request.getContextPath() + redirectURL);//Url de retorno desde Google
        url.append("&response_type=code");//Tipo de Respuesta codigo, estado para garantizar que vuelvo de google.
        url.append("&client_id=" + clientID);//ID del cliente (Consola de Desarrolladores)
        url.append("&scope=https://www.googleapis.com/auth/plus.login+email");//Tipo de autorizacion que va a dar Google


        return url.toString();
    }

    private JSONObject ObtenerInfoUsuario(HttpServletRequest request) throws ServletException, IOException
    {

        JSONObject retorno = null;

        if(request.getParameter("error")  != null){

            log.error("GPLUS Google retorna un error");

        }else{

            log.info("GPLUS POST to Google for authorization Code");

            String code = request.getParameter("code");

            String post = Ejecutar_POST("https://accounts.google.com/o/oauth2/token", ImmutableMap.<String, String>builder()
                          .put("code", code)
                          .put("client_id", clientID)
                          .put("client_secret", clientSecret)
                          .put("redirect_uri", appDomain + request.getContextPath() + redirectURL)
                          .put("grant_type", "authorization_code").build());

            JSONObject jsonObject = null;

            log.info("GPLUS Trying to Parse JSON and get Authorization Code");

            try{
                jsonObject = Parsear_JSON(post);
            }catch (ParseException e){
                throw new RuntimeException("GPLUS JSON returned by Google is null or can't be parsed");
            }

            log.info("GPLUS GET to Google to get user information");

            String usuarioJSON = Ejecutar_GET("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + ((String) jsonObject.get("access_token")));

            try{
                retorno = Parsear_JSON(usuarioJSON);
                log.info("GPLUS JSON Object created for user.");
            }catch (ParseException e){
                throw new RuntimeException("GPLUS JSON returned by Google is null or can't be parsed");
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
        log.info("GPlus New EPerson Created, setting up information");
        ePerson.setEmail(email);
        ePerson.setFirstName(nombre);
        ePerson.setLastName(apellido);
        ePerson.setCanLogIn(true);
        log.info("GPlus Initializing EPerson");
        AuthenticationManager.initEPerson(context, request, ePerson);
        log.info("GPlus Updating EPerson Metadata");
        ePerson.update();

        context.commit();

        context.restoreAuthSystemState();

        return ePerson;

    }
}


