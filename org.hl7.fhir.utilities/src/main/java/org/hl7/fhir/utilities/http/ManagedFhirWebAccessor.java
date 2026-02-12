package org.hl7.fhir.utilities.http;

import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import org.hl7.fhir.utilities.ToolingClientLogger;
import org.hl7.fhir.utilities.http.okhttpimpl.LoggingInterceptor;
import org.hl7.fhir.utilities.http.okhttpimpl.ProxyAuthenticator;
import org.hl7.fhir.utilities.http.okhttpimpl.RetryInterceptor;
import org.hl7.fhir.utilities.settings.ServerDetailsPOJO;

import java.io.IOException;
import java.net.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
public class ManagedFhirWebAccessor extends ManagedWebAccessorBase<ManagedFhirWebAccessor> {

  /**
   * The singleton instance of the HttpClient, used for all requests.
   */
  private static OkHttpClient okHttpClient;

  private long timeout;
  private TimeUnit timeoutUnit;
  private int retries;
  private ToolingClientLogger logger;
  private LoggingInterceptor loggingInterceptor;

  public ManagedFhirWebAccessor withTimeout(long timeout, TimeUnit timeoutUnit) {
    this.timeout = timeout;
    this.timeoutUnit = timeoutUnit;
    return this;
  }

  public ManagedFhirWebAccessor withRetries(int retries) {
    this.retries = retries;
    return this;
  }

  public ManagedFhirWebAccessor withLogger(ToolingClientLogger logger) {
    this.logger = logger;
    this.loggingInterceptor = new LoggingInterceptor(logger);
    return this;
  }

  public ManagedFhirWebAccessor(String userAgent, List<ServerDetailsPOJO> serverAuthDetails) {
    super(Arrays.asList("fhir"), userAgent, serverAuthDetails);
    this.timeout = 5000;
    this.timeoutUnit = TimeUnit.MILLISECONDS;
  }

  protected HTTPRequest httpRequestWithDefaultHeaders(HTTPRequest request) {
    List<HTTPHeader> headers = new ArrayList<>();
    if (HTTPHeaderUtil.getSingleHeader(request.getHeaders(), HTTPHeaderUtil.USER_AGENT) == null
      && getUserAgent() != null) {
      headers.add(new HTTPHeader(HTTPHeaderUtil.USER_AGENT, getUserAgent()));
    }
    request.getHeaders().forEach(headers::add);
    return request.withHeaders(headers);
  }

  protected HTTPRequest requestWithManagedHeaders(HTTPRequest httpRequest) {
    HTTPRequest requestWithDefaultHeaders = httpRequestWithDefaultHeaders(httpRequest);

    List<HTTPHeader> headers = new ArrayList<>();
    requestWithDefaultHeaders.getHeaders().forEach(headers::add);

    for (Map.Entry<String, String> entry : this.getHeaders().entrySet()) {
      headers.add(new HTTPHeader(entry.getKey(), entry.getValue()));
    }

    if (getAuthenticationMode() != null) {
      if (getAuthenticationMode() != HTTPAuthenticationMode.NONE) {
        switch (getAuthenticationMode()) {
          case BASIC:
            final String basicCredential = Credentials.basic(getUsername(), getPassword());
            headers.add(new HTTPHeader("Authorization", basicCredential));
            break;
          case TOKEN:
            String tokenCredential = "Bearer " + getToken();
            headers.add(new HTTPHeader("Authorization", tokenCredential));
            break;
          case APIKEY:
            String apiKeyCredential = getToken();
            headers.add(new HTTPHeader("Api-Key", apiKeyCredential));
            break;
        }
      }
    } else {
      ServerDetailsPOJO settings = ManagedWebAccessUtils.getServer(getServerTypes(), httpRequest.getUrl().toString(), getServerAuthDetails());
      if (settings != null) {
        switch (settings.getAuthenticationType()) {
          case "basic":
            final String basicCredential = Credentials.basic(settings.getUsername(), settings.getPassword());
            headers.add(new HTTPHeader("Authorization", basicCredential));
            break;
          case "token":
            String tokenCredential = "Bearer " + settings.getToken();
            headers.add(new HTTPHeader("Authorization", tokenCredential));
            break;
          case "apikey":
            String apiKeyCredential = settings.getApikey();
            headers.add(new HTTPHeader("Api-Key", apiKeyCredential));
            break;
        }
      }
    }
    return httpRequest.withHeaders(headers);
  }

  public HTTPResult httpCall(HTTPRequest httpRequest) throws IOException {
    switch (ManagedWebAccess.getAccessPolicy()) {
      case DIRECT:

        HTTPRequest httpRequestWithDirectHeaders = requestWithManagedHeaders(httpRequest);
        assert httpRequestWithDirectHeaders.getUrl() != null;

        RequestBody body = httpRequestWithDirectHeaders.getBody() == null ? null : RequestBody.create(httpRequestWithDirectHeaders.getBody());
        Request.Builder requestBuilder = new Request.Builder()
          .url(httpRequestWithDirectHeaders.getUrl())
          .method(httpRequestWithDirectHeaders.getMethod().name(), body);

        for (HTTPHeader header : httpRequestWithDirectHeaders.getHeaders()) {
          requestBuilder.addHeader(header.getName(), header.getValue());
        }
        OkHttpClient okHttpClient = getOkHttpClient();
        //TODO check and throw based on httpRequest:

        if (!ManagedWebAccess.inAllowedPaths(httpRequestWithDirectHeaders.getUrl().toString())) {
              throw new IOException("The pathname '"+httpRequestWithDirectHeaders.getUrl().toString()+"' cannot be accessed by policy");}
        Response response = okHttpClient.newCall(requestBuilder.build()).execute();
        return getHTTPResult(response);
      case MANAGED:
        HTTPRequest httpRequestWithManagedHeaders = requestWithManagedHeaders(httpRequest);
        assert httpRequestWithManagedHeaders.getUrl() != null;
        return ManagedWebAccess.getFhirWebAccessor().httpCall(httpRequestWithManagedHeaders);
      case PROHIBITED:
        throw new IOException("Access to the internet is not allowed by local security policy");
      default:
        throw new IOException("Internal Error");
    }
  }

  private HTTPResult getHTTPResult(Response execute) throws IOException {
    return new HTTPResult(execute.request().url().toString(), execute.code(), execute.message(), execute.header("Content-Type"), execute.body() != null && execute.body().contentLength() != 0 ? execute.body().bytes() : null, getHeadersFromResponse(execute));
  }

  private Iterable<HTTPHeader> getHeadersFromResponse(Response response) {
    List<HTTPHeader> headers = new ArrayList<>();
    for (String name : response.headers().names()) {
      headers.add(new HTTPHeader(name, response.header(name)));
    }
    return headers;
  }

  private OkHttpClient getOkHttpClient() {
    if (okHttpClient == null) {
      okHttpClient = new OkHttpClient();
    }
    OkHttpClient.Builder builder = okHttpClient.newBuilder();
    if (logger != null) builder.addInterceptor(loggingInterceptor);
    builder.addInterceptor(new RetryInterceptor(retries));
    builder.proxyAuthenticator(new ProxyAuthenticator());
    builder.proxySelector(new ProxySelector() {
      @Override
      public List<Proxy> select(URI uri) {
        final List<Proxy> proxyList = new ArrayList<>();

        final String host = uri.getHost();
        final String httpProxyHost = System.getProperty("http.proxyHost");
        final String httpProxyPort = System.getProperty("http.proxyPort");
        final String httpsProxyHost = System.getProperty("https.proxyHost");
        final String httpsProxyPort = System.getProperty("https.proxyPort");

        if (uri.getScheme().equals("http")) {
          if (httpProxyHost != null && httpProxyPort != null && hostNotInNoProxy(host)) {
            proxyList.add(new Proxy(Proxy.Type.HTTP,
              new InetSocketAddress(httpProxyHost, Integer.parseInt(httpProxyPort))));
          }
        }
        if (uri.getScheme().equals("https")) {
          if (httpsProxyHost != null && httpProxyPort != null && hostNotInNoProxy(host)) {
            proxyList.add(new Proxy(Proxy.Type.HTTP,
              new InetSocketAddress(httpsProxyHost, Integer.parseInt(httpsProxyPort))));
          }
        }
        proxyList.add(Proxy.NO_PROXY);
        return proxyList;
      }

      private boolean hostNotInNoProxy(String host) {
        String nonProxyHostsString = System.getProperty("http.nonProxyHosts");
        if (nonProxyHostsString == null) {
          return true;
        }
        nonProxyHostsString = nonProxyHostsString
          .replace(".", "\\.")
          .replace("*", ".*");
        List<String> nonProxyHosts = Arrays.asList(nonProxyHostsString.split("\\|"));
        return nonProxyHosts.stream().noneMatch(host::matches);
      }

      @Override
      public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
        log.error("Connection to {} failed!\nProxy: {}\n{}", uri, sa, ioe.getMessage());
      }
    });
    return builder.connectTimeout(timeout, timeoutUnit)
      .writeTimeout(timeout, timeoutUnit)
      .readTimeout(timeout, timeoutUnit).build();
  }

}
