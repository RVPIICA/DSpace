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
import org.dspace.eperson.Group;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.google.common.collect.ImmutableMap;

/**
 * @author Randall Vargas Padilla
 * @version $Revision$
 *
 * Clase implementada para autenticar a los usuarios
 * por medio del sistema OAuth 2.0 de Google.
 */
public class GPlusAuthentication implements AuthenticationMethod {


    private final String redirectURL = "/gplus-login";//Nombre del path donde se mapea el servlet de procesamiento

    private static Logger log = Logger.getLogger(GPlusAuthentication.class);//Bitacora de status

    /** Obtengo los datos de configuración que requiero**/
    private String clientID = ConfigurationManager.getProperty("authentication-gplus", "client_id");
    private String clientSecret = ConfigurationManager.getProperty("authentication-gplus", "client_secret");
    private String appDomain = ConfigurationManager.getProperty("authentication-gplus", "domain");

    /*Implementado igual que en Password Login para verificar de acuerdo al dominio si el usuario puede ingresar.*/
    public boolean canSelfRegister(Context context, HttpServletRequest request, String email) throws SQLException {
        String domains = ConfigurationManager.getProperty("authentication-gplus", "domain.valid");
        if(domains != null && !domains.trim().equals("")) {
            String[] options = domains.trim().split(",");
            email = email.trim().toLowerCase();

            for(int i = 0; i < options.length; ++i) {
                String check = options[i].trim().toLowerCase();
                if(email.endsWith(check)) {
                    return true;
                }
            }

            return false;
        } else {
            return true;
        }
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

    /*
     *Método principal de autenticación, es invocado desde GPlusServlet.java
     * después de que el usuario obtine un código de autorización tras proporcionar
     * usuario, clave y consentimiento en la página de Google.
     * Ejecuta POST para obtener el token de autorización intercambiando
     * el client_id y client_secret. Posteriormente ejecuto
     * el GET que me retorna el JSON con la información del usuario
     * que utilizo para autenticar o generar un nuevo usuario en
     * caso que no sea un usuario registrado.
     */
    public int authenticate(Context context,
                            String username,
                            String password,
                            String realm,
                            HttpServletRequest request)
            throws SQLException
    {
        String code = request.getParameter("code");

        if(code == null){//Usuario no se autentica o no da consentimiento a la aplicacion en goolge

            log.info("GPlus User didn't consent application, not authenticating");
            return CERT_REQUIRED;

        }else{//El formulario de autenticación (Página de autenticación de Google me retornó un código de autorización)

            log.info("GPLUS Attempting to authenticate JSON User and get it's information");

            JSONObject usuario = null;

            try{
                usuario = ObtenerInfoUsuario(request);//Intento obtener la información de usuario desde Google
            }catch (Exception e){
                log.error(e.getMessage());
                return BAD_ARGS;
            }

            String email = (String) usuario.get("email");
            String nombre = (String) usuario.get("given_name");
            String apellido = (String) usuario.get("family_name");

            log.info("GPLUS Managed to get User data");

            EPerson ePerson = null;

            try{
                //Trato de encontrar la EPerson que coincida con el correo
                log.info("GPLUS Trying to find EPerson by Email");
                ePerson = EPerson.findByEmail(context, email);

                if(ePerson == null){//No encontré la EPerson
                    log.info("GPLUS EPerson not found, trying to register into system");
                    if(canSelfRegister(context, request, email)){//Compruebo si la persona puede registrarse (Pertenece al IICA)
                        ePerson = RegistrarEPerson(context, request, email, nombre, apellido);//Registro una nueva EPerson al sistema
                        AsignarGrupo(ePerson, context);
                    }else{
                        log.info("GPLUS This email domain can't be registered");
                        return BAD_CREDENTIALS;
                    }
                }

                log.info("GPlus Logging in EPerson");

                context.setCurrentUser(ePerson);
                AuthenticationManager.initEPerson(context, request, ePerson);

                log.info("GPlus Login Succes");

                return SUCCESS;//Autenticación Exitosa!!

            }catch (AuthorizeException e){
                log.trace("GPLUS Failed to authorize looking up EPerson", e);
                return CERT_REQUIRED;
            }

        }
    }
    /*
     * Redirecciona a la dirección de LogIn (En este caso la página de autenticación de Google
     * Es la única vez que tengo que redireccionar ya que lo demás se realiza por medio de
     * llamados POST y GET.
     */
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
    /*
     * Asigna los nuevos usuarios registrados al
     * grupo establecido en el archvio
     * authentication-gplus.cfg en el parametro
     * group.name
     */
    private void AsignarGrupo(EPerson ePerson, Context context)
    {
        String nombreGrupo = ConfigurationManager.getProperty("authentication-gplus", "group.name");

        try{
            log.trace("GPlus trying to find group: " + nombreGrupo);
            Group grupo = Group.findByName(context, nombreGrupo);

            if(grupo != null){
                log.trace("GPlus registering user in group: " + nombreGrupo);
                grupo.addMember(ePerson);
                grupo.update();
                context.commit();
            }else{
                log.trace("GPlus Group: " + nombreGrupo + " not found.");
            }

        }catch (SQLException ex){
            log.error("GPLUS Error ocurred trying to add user to a group. SQLException");
        }catch (AuthorizeException ex){
            log.error("GPlus Error ocurred trying to add user to a group. AuthorizationException");
        }

    }

    //Otras clases para Login de Google.

    /*
     *Forma el URL para redireccionar (Donde digito usuario y contraseña de google)
     */
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


            //Cambio el código de autorización que me brinda google así como client_secret y client_id por authorization_code
            String post = Ejecutar_POST("https://accounts.google.com/o/oauth2/token", ImmutableMap.<String, String>builder()
                          .put("code", code)
                          .put("client_id", clientID)
                          .put("client_secret", clientSecret)
                          .put("redirect_uri", appDomain + request.getContextPath() + redirectURL)
                          .put("grant_type", "authorization_code").build());

            JSONObject jsonObject = null;

            log.info("GPLUS Trying to Parse JSON and get Authorization Code");

            try{
                //Parseo el JSON que contiene el código de autorización.
                jsonObject = Parsear_JSON(post);
            }catch (ParseException e){
                throw new RuntimeException("GPLUS JSON returned by Google is null or can't be parsed");
            }

            log.info("GPLUS GET to Google to get user information");

            //Ejecuto GET que incluye la información del usuario en formato JSON
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
    /*Utilizado para registrar una nueva EPerson utilizando Nombre, Apellido y Correo proporcionado por la consulta a Google*/
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


