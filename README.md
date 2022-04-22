## Authentication & Authorization

### Spring Security 사용하기

- Spring Boot Dependencies에 Spring Security 추가하기

	```java
		dependencies {
			...
	    implementation 'org.springframework.boot:spring-boot-starter-security'
			...
	}
	```

- 적절한 패키지 생성 및 Security Fitler Configuration 생성하기

	**com.example.jwt.config.SecurityConfig.java**

	- 클래스 선언부에  `@Configuration` , `@EnableWebSecurity` 추가
	- Dependency Injection 을 위해 생성자 주입 방식 이용시 `@RequiredArgsConstructor` 추가
	- *`WebSecurityConfigurerAdapter`* 상속

	```java
	@Configuration
	@EnableWebSecurity
	@RequiredArgsConstructor
	public class SecurityConfig extendsWebSecurityConfigurerAdapter{
	
	    private final CorsFilter corsFilter;
	    private final UserRepository userRepository;
	
	    @Override
	    protected void configure(HttpSecurity http) throws Exception {
	
	//  http.addFilterAfter(new MyFilter3(), BasicAuthenticationFilter.class); // Security Filter Chain이 끝나고 기본 필터가 실행됨,  BasicAuthenticationFilter직후에 동작
	//  http.addFilterBefore(new MyFilter3(), BasicAuthenticationFilter.class); // Security Filter Chain이 끝나고 기본 필터가 실행됨 , BasicAuthenticationFilter직전에 동작
	
	http.csrf().disable();
	        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
	                .and()
	                .addFilter(corsFilter)// @CrossOrigin ->인증(X),시큐리티 필터에 등록 ->인증(O)
									.formLogin().disable()
	                .httpBasic().disable()
	                .addFilter(new JwtAuthenticationFilter(authenticationManager()))// AuthenticationManager
									.addFilter(new JwtAuthorizationFilter(authenticationManager(),userRepository ))
	                .authorizeRequests()
	                .antMatchers("/api/v1/user/**")
	                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
	                .antMatchers("/api/v1/manager/**")
	                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
	                .antMatchers("/api/v1/admin/**")
	                .access("hasRole('ROLE_ADMIN')")
	                .anyRequest().permitAll();
	    }
	}
	```

	- `addFilterBefore(Filter, class)`, `addFilterAfter(Filter, class)` : 특정 필터 전후로 실행될 필터 설정
	- `sessionCreationPolicy(SessionCreationPolicy.STATELESS)` : 인증 처리 관점에서 스프링 시큐리티가 더 이상 세션쿠키 방식의 인증 메카니즘으로 인증처리를 하지 않겠다는 의미
	- `http.csrf().disable()` : 토큰을 이용할 경우 session 기반 인증과는 다르게 stateless하기 때문에 서버에 인증정보를 보관하지 않는다.
	- `formLogin().disable().httpBasic().disable()` : 토큰 기반 인증시 form login 사용하지 않음, Bearer HTTP Authentication 방식

### 커스텀 필터 사용하기

커스텀 필터의 경우 기본적으로 Security Filter Chain 이 모두 실행된 이후에 실행된다. Security Filter 사이에 동작하도록 하기 원한다면 `addFilterBefore(Filter, class)`, `addFilterAfter(Filter, class)`  를 이용,

- 적절한 패키지에 커스텀 필터 생성

	**com.example.jwt.filter.MyFilter1.java**

	- Filter 상속 및 메서드 구현

	```java
	public class MyFilter1 implements Filter {
	
	    @Override
	    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
	        System.out.println("Filter1");
	        chain.doFilter(request,response);
	    }
	}
	```

- 적절한 패키지에 Filter Configuration 생성

	**com.example.jwt.config.FilterConfig.java**

	- 클래스 선언부에 `@Configuration`
	- 커스텀 필터 빈으로 등록

	```java
	@Configuration
	public class FilterConfig {
	
	    @Bean
	    public FilterRegistrationBean<MyFilter1> filter1(){
	        FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
	        bean.addUrlPatterns("/*");
	        bean.setOrder(1);//번호가 낮을수록 먼저 실행
	return bean;
	    }
	    @Bean
	    public FilterRegistrationBean<MyFilter2> filter2(){
	        FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<>(new MyFilter2());
	        bean.addUrlPatterns("/*");
	        bean.setOrder(0);
	        return bean;
	    }
	}
	```

### Authentication Filter

**com.example.jwt.filter.JwtAuthenticationFilter.java**

- `UsernamePasswordAuthenticationFilter` 상속 후 메서드 구현

- `attemptAuthentication` : 인증 방식 메서드

	1. ObjectManager를 통해 Request로부터  username, password를 받는다

	2. UsernamePasswordAuthenticationToken를 통해 토큰을 생성

	3. AuthenticationManager(interface)에 UsernamePasswordAuthenticationToken를 입력하여 인증 프로세스 진행(ProviderManager)(구현체)

	4. PrincipalDetailService가 호출 됨, loadUserByUsername메서드 실행하여 유저 세부정보 리턴(→ AuthenticationProvider)

	5. 인증과정이 정상실행 되면 (DB에 있는 username, password가 일치한다) Authentication객체 리턴

		> return 함으로써 Authentication객체가 session영역에 저장됨. 굳이 JWT토큰을 사용하면서 세션을 만들 이유가 없음, 리턴의 이유는 권한관리를 security가 대신 해주기 때문에 편의로 하는것

- `successfulAuthentication` : 인증 성공시 동작 메서드

	1. PrincipalDetail을 세션에 담는다(선택 사항,권한 관리를 위해서)
	2. JWT토큰을 만들어서 응답해준다

```java
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

		/* login 요청을 하면 로그인 시도를 위해서 실행되는 함수 */

    @Override
    public Authentication ㅊ(HttpServletRequest request, HttpServletResponse response) throwsAuthenticationException {

        try {
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            log.info("Input Value : {} ", user);

            UsernamePasswordAuthenticationToken authenticationToken
                = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            PrincipalDetails principalDetail = (PrincipalDetails) authentication.getPrincipal();
            log.info("Login successful : {}", principalDetail.getUser().getUsername());

            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

		/*
    attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 메서드 실행
    JWT 토큰을 만들어서 request 한 사용자에게 JWT 토큰을 response 해준다.
    */

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        PrincipalDetails principalDetail = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
            .withSubject(principalDetail.getUsername())
            .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
            .withClaim("id", principalDetail.getUser().getId())
            .withClaim("username", principalDetail.getUser().getUsername())
            .sign(Algorithm.HMAC512(SECRET));
        response.addHeader(HEADER_STRING, TOKEN_PREFIX + jwtToken);
        super.successfulAuthentication(request, response, chain, authResult);
    }
}
```

### Authorization Filter

**com.example.jwt.filter.JwtAuthorizationFilter.java**

- `BasicAuthenticationFilter` 상속후 메서드 구현

- (선택사항) JWT Properties 변수를 저장해둔 인터페이스 생성

	```java
		public interface JwtProperties {
	    String SECRET = "jby";
	    Integer EXPIRATION_TIME = 1000 * 60 * 30;
	    String TOKEN_PREFIX = "Bearer ";
	    String HEADER_STRING = "Authorization";
	}
	```

- `doFilterInternal` : 인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게됨.

- Request의 헤더로부터 JWT토큰을 가져오고, 정상 토큰인지 검증 한다

- JWT 토큰 서명을 통해서 서명이 정상이면 유저정보, 권한을 담아 Authentication 객체를 만들어준다.

```java
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final UserRepository userRepository;
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String jwtHeader = request.getHeader(HEADER_STRING);

        /* JWT 토큰을 검증을 해서 정상적인 사용자인지 확인 */
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }

        String jwtToken = request.getHeader(HEADER_STRING).replace(TOKEN_PREFIX, "");
        String username = JWT.require(Algorithm.HMAC512(SECRET)).build().verify(jwtToken).getClaim("username").asString();

        if (username != null) {
            User userEntity = userRepository.findByUsername(username);
            PrincipalDetails principalDetail = new PrincipalDetails(userEntity);

            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetail, null, principalDetail.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request, response);
        }
    }
}
```

### User, PrincipalDetails, PrincipalDetailsService

- User

	```java
	@Entity
	@Data
	@NoArgsConstructor
	@AllArgsConstructor
	public class User {
	
	    @Id
	    @GeneratedValue(strategy = GenerationType.IDENTITY)
	    private Long id;
	    private String username;
	    private String password;
	    private String roles;// USER,ADMIN
	
	public List<String> getRoleList() {
	        if (this.roles.length() > 0) return Arrays.asList(this.roles.split(","));
	        return new ArrayList<>();
	    }
	}
	```

- PrincipalDetails

	- UserDetails 구현체

	```java
	@Getter
	public class PrincipalDetails implements UserDetails {
	
	    private User user;
	
	    public PrincipalDetails(User user) {
	        this.user = user;
	    }
	
	    @Override
	    public Collection<? extends GrantedAuthority> getAuthorities() {
	        Collection<GrantedAuthority> authorities = new ArrayList<>();
	        user.getRoleList().forEach(r ->{
	            authorities.add(() -> r);
	        });
	        return authorities;
	    }
	
	    @Override
	    public String getPassword() {
	        return user.getPassword();
	    }
	
	    @Override
	    public String getUsername() {
	        return user.getUsername();
	    }
	
	    @Override
	    public boolean isAccountNonExpired() {
	        return true;
	    }
	
	    @Override
	    public boolean isAccountNonLocked() {
	        return true;
	    }
	
	    @Override
	    public boolean isCredentialsNonExpired() {
	        return true;
	    }
	
	    @Override
	    public boolean isEnabled() {
	        return true;
	    }
	}
	```

- PrincipalDetailsService

	- UserDetailsService 구현체
	- /login 으로 접근시 인증방식 진행시 호출됨

	```java
	@Service
	@RequiredArgsConstructor
	public class PrincipalDetailsService implements UserDetailsService {
	
	    private final UserRepository userRepository;
	
	    @Override
	    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
	
	        User userEntity = userRepository.findByUsername(username);
	        return new PrincipalDetails(userEntity);
	    }
	}
	```