package com.github.jackofmosttrades.ykpiv.security;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;

/**
 * A simple server implementation that echos back one byte from each connection. Serves over SSL using the provided
 * SSLContext, and will require client authentication if the clientAuth constructor parameter is true.
 */
public class EchoServer implements AutoCloseable {

    private final Listener listener;
    private final Thread thread;

    public EchoServer(SSLContext sslContext, boolean clientAuth) {
        this.listener = new Listener(sslContext, clientAuth);
        this.thread = new Thread(listener);
        this.thread.start();
    }

    public int getPort() {
        return listener.port;
    }

    private static class Listener implements Runnable {
        private final SSLServerSocket serverSocket;
        private final int port;
        private boolean shuttingDown = false;

        public Listener(SSLContext sslContext, boolean clientAuth) {
            try {
                serverSocket = (SSLServerSocket)sslContext.getServerSocketFactory().createServerSocket(0);
                if (clientAuth) {
                    serverSocket.setNeedClientAuth(true);
                }
                port = serverSocket.getLocalPort();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public void run() {
            while (!shuttingDown) {
                try {
                    try (Socket socket = serverSocket.accept()) {
                        try (InputStream inputStream = socket.getInputStream();
                             OutputStream outputStream = socket.getOutputStream()) {

                            int b = inputStream.read();
                            outputStream.write(b);
                        }
                    }
                } catch (SocketException e) {
                    if (!e.getMessage().equals("Socket closed")) {
                        e.printStackTrace();
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (!serverSocket.isClosed()) {
                try {
                    serverSocket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    @Override
    public void close() {
        listener.shuttingDown = true;
        try {
            listener.serverSocket.close();
            thread.join();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }
}
