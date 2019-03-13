package com.kidventure.config.security.filter;

import com.kidventure.config.security.constants.SecurityConstants;
import org.apache.logging.log4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
class CorsFilter implements Filter {
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(this.getClass());

    private static final boolean CONDITION = true;

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(
            final ServletRequest req,
            final ServletResponse res, final FilterChain chain) throws IOException, ServletException {
        logger.info("inside cors filter");
        final HttpServletResponse response = (HttpServletResponse) res;
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "POST, GET, PUT, OPTIONS, DELETE, PATCH");
        response.setHeader("Access-Control-Max-Age", "3600");
        response.setHeader("Access-Control-Allow-Headers", "authorization, Content-Type");
        response.setHeader("Access-Control-Expose-Headers", "authorization, Content-Type");

        final HttpServletRequest request = (HttpServletRequest) req;
        logger.info("request::" + request.getMethod());
        logger.info("request::" + request.getRemoteHost());
        if (request.getMethod().equals("OPTIONS")) {
            logger.info("method equals options");
            try {
                response.getWriter().print("OK");
                response.getWriter().flush();
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            logger.info("method not equal to option");
            if (CONDITION) {
                logger.info("inside condition");
                String uuid = request.getHeader("uuid");
                logger.info("uuid:::" + uuid);
                HeaderMapRequestWrapper requestWrapper = new HeaderMapRequestWrapper(request);
                StringBuffer url = request.getRequestURL();
                logger.info("url::" + url);
                String uri = request.getRequestURI();
                logger.info("uri:::" + uri);
                String host = url.substring(0, url.indexOf(uri));
                logger.info("host::" + host);
                requestWrapper.addHeader(SecurityConstants.UUID, uuid);
                logger.info("response::"+response);
                logger.info("response::"+response.getHeader(uuid));
                logger.info("response::"+response.getHeaderNames());
                chain.doFilter(requestWrapper, response);
            } else {
                ((HttpServletResponse) response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
            }
        }
    }

    @Override
    public void destroy() {

    }
}

