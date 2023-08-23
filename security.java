@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AccessDecisionFilter accessDecisionFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .addFilterBefore(accessDecisionFilter, UsernamePasswordAuthenticationFilter.class)
            .authorizeRequests()
                .antMatchers("/public/**").permitAll() // Publicly accessible URLs
                .anyRequest().authenticated()
                .and()
            .oauth2ResourceServer()
                .jwt(); // Use JWT for token validation
    }
}
