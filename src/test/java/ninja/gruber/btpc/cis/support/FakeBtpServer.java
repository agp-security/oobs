// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.cis.support;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class FakeBtpServer implements AutoCloseable {

    private final HttpServer server;
    private final Map<String, Response> routes = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> hits = new ConcurrentHashMap<>();

    public FakeBtpServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String key = exchange.getRequestMethod() + " " + exchange.getRequestURI().getPath();
            hits.computeIfAbsent(key, k -> new AtomicInteger()).incrementAndGet();
            Response r = routes.get(key);
            byte[] body;
            int status;
            if (r == null) {
                status = 404;
                body = ("no stub for " + key).getBytes(StandardCharsets.UTF_8);
            } else {
                status = r.status;
                body = r.body.getBytes(StandardCharsets.UTF_8);
                if (r.contentType != null) {
                    exchange.getResponseHeaders().add("Content-Type", r.contentType);
                }
            }
            // Drain the body so connections close cleanly.
            try (InputStream is = exchange.getRequestBody()) { is.readAllBytes(); }
            exchange.sendResponseHeaders(status, body.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
        });
        server.start();
    }

    public String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    public void respondWith(String method, String path, int status, String contentType, String body) {
        routes.put(method + " " + path, new Response(status, contentType, body));
    }

    public int hits(String method, String path) {
        AtomicInteger c = hits.get(method + " " + path);
        return c == null ? 0 : c.get();
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private record Response(int status, String contentType, String body) {}
}
