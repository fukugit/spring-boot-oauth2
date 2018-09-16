package jp.co.example;

import java.security.Principal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.CompositeFilter;


@SpringBootApplication
@EnableOAuth2Client
@RestController
public class App extends WebSecurityConfigurerAdapter 
{
  @Autowired
  OAuth2ClientContext oauth2ClientContext;

  @Bean
  @ConfigurationProperties("github.client")
  public AuthorizationCodeResourceDetails github() {
      return new AuthorizationCodeResourceDetails();
  }

  @Bean
  @ConfigurationProperties("github.resource")
  public ResourceServerProperties githubResource() {
      return new ResourceServerProperties();
  }
  
  @RequestMapping("/user")
  public String user(Principal principal) {
    return principal.getName();
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
    .antMatcher("/**")
    .authorizeRequests()
      .antMatchers("/", "/login**", "/webjars/**", "/error**")
      .permitAll()
    .anyRequest()
      .authenticated()
      .and().addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
  }
  
  private Filter ssoFilter() {
    CompositeFilter filter = new CompositeFilter();
    List<Filter> filters = new ArrayList<>();

    OAuth2ClientAuthenticationProcessingFilter githubFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/github");
    OAuth2RestTemplate githubTemplate = new OAuth2RestTemplate(github(), oauth2ClientContext);
    githubFilter.setRestTemplate(githubTemplate);
    UserInfoTokenServices tokenServices = new UserInfoTokenServices(githubResource().getUserInfoUri(), github().getClientId());
    tokenServices.setRestTemplate(githubTemplate);
    githubFilter.setTokenServices(tokenServices);
    filters.add(githubFilter);

    filter.setFilters(filters);
    return filter;
  }
  
  @Bean
  public FilterRegistrationBean oauth2ClientFilterRegistration(
      OAuth2ClientContextFilter filter) {
    FilterRegistrationBean registration = new FilterRegistrationBean();
    registration.setFilter(filter);
    registration.setOrder(-100);
    return registration;
  }
  
  public static void main(String[] args) {
      SpringApplication.run(App.class, args);
  }

}

