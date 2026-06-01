// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestSizeFilter extends OncePerRequestFilter {

    private final long maxBytes;

    public RequestSizeFilter(
            @Value("${btpc.security.max-request-bytes:131072}") long maxBytes) {
        this.maxBytes = maxBytes;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        // Fast path: an honestly declared over-size body is rejected up front.
        // A chunked request declares length -1, so it slips past this check -
        // the wrapper below caps it at read time so it can't exhaust memory.
        if (req.getContentLengthLong() > maxBytes) {
            res.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
            res.setContentType("application/json");
            res.getWriter().write("{\"error\":\"payload_too_large\",\"message\":\"request body exceeds "
                    + maxBytes + " bytes\"}");
            return;
        }
        chain.doFilter(new LimitedRequest(req, maxBytes), res);
    }

    // Caps the request body stream so an undeclared / under-declared length
    // (e.g. Transfer-Encoding: chunked) can't stream past the budget. Reading
    // past the cap throws IOException, which Spring surfaces as a 400 before any
    // unbounded buffering happens.
    private static final class LimitedRequest extends HttpServletRequestWrapper {
        private final long max;

        LimitedRequest(HttpServletRequest req, long max) {
            super(req);
            this.max = max;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            return new LimitingStream(getRequest().getInputStream(), max);
        }

        @Override
        public BufferedReader getReader() throws IOException {
            String enc = getCharacterEncoding();
            return new BufferedReader(new InputStreamReader(getInputStream(),
                    enc != null ? enc : StandardCharsets.UTF_8.name()));
        }
    }

    private static final class LimitingStream extends ServletInputStream {
        private final ServletInputStream delegate;
        private final long max;
        private long count;

        LimitingStream(ServletInputStream delegate, long max) {
            this.delegate = delegate;
            this.max = max;
        }

        private int tally(int n) throws IOException {
            if (n > 0 && (count += n) > max) {
                throw new IOException("request body exceeds " + max + " bytes");
            }
            return n;
        }

        @Override public int read() throws IOException {
            int b = delegate.read();
            if (b != -1) tally(1);
            return b;
        }

        @Override public int read(byte[] b, int off, int len) throws IOException {
            return tally(delegate.read(b, off, len));
        }

        @Override public boolean isFinished() { return delegate.isFinished(); }
        @Override public boolean isReady() { return delegate.isReady(); }
        @Override public void setReadListener(ReadListener l) { delegate.setReadListener(l); }
    }
}
