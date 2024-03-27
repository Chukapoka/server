package com.chukapoka.server.common.authority;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** swagger 의존성만 설정해도 자동 적용되지만, jwt 토큰값을 확인하기 위한 설정 */
@Configuration
public class SwaggerConfig {


    /** SwaggerConfig의 openAPI 함수에 security schemes를 추가
     * addList 부분과 addSecuritySchemes의 이름 부분은 변경이 가능하지만 둘 다 같은 이름이어야 함 */
    @Bean
    public OpenAPI openAPI(){
        return new OpenAPI().addSecurityItem(new SecurityRequirement().addList("JWT"))
                .components(new Components().addSecuritySchemes("JWT", createAPIKeyScheme()))
                .info(new Info().title("Chukapoka API")
                        .description("This is Chukapoka API")
                        .version("v2.2.0"));
    }
    /** JWT를 적용하려면 confugure에 JWT SecurityScheme이 필요 */
    private SecurityScheme createAPIKeyScheme() {
        return new SecurityScheme().type(SecurityScheme.Type.HTTP)
                .bearerFormat("JWT")
                .scheme("bearer");
    }
}
