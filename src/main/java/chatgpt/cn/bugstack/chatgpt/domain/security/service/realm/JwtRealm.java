package chatgpt.cn.bugstack.chatgpt.domain.security.service.realm;

import chatgpt.cn.bugstack.chatgpt.domain.security.model.vo.JwtToken;
import chatgpt.cn.bugstack.chatgpt.domain.security.service.JwtUtil;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JwtRealm extends AuthorizingRealm {

    private Logger logger = LoggerFactory.getLogger(JwtRealm.class);

    private static JwtUtil jwtUtil = new JwtUtil();

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof JwtToken;
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // 暂时不需要实现
        return null;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // 从AuthenticationToken中获取jwt字符串。
        String jwt = (String) token.getPrincipal();
        // 检查jwt是否为空，如果为空则抛出空指针异常。
        if (jwt == null) {
            throw new NullPointerException("jwtToken 不允许为空");
        }
        // 使用jwtUtil验证jwt的有效性，如果无效则抛出UnknownAccountException。
        if (!jwtUtil.isVerify(jwt)) {
            throw new UnknownAccountException();
        }
        // 可以获取username信息，并做一些处理
        String username = (String) jwtUtil.decode(jwt).get("username");
        logger.info("鉴权用户 username：{}", username);
        return new SimpleAuthenticationInfo(jwt, jwt, "JwtRealm");
    }

}