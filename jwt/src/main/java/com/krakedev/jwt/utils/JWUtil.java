package com.krakedev.jwt.utils;

import java.sql.Date;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.krakedev.jwt.services.UsuarioService;

public class JWUtil {
	private static final Logger logger = LogManager.getLogger(UsuarioService.class);
	private static final String CLAVE_SECRETA = "LaClaveSecretaMeTieneJodioo123456!";
	private static final String EMISOR = "KrakeDevBackend";
	private static final long TIEMPO_EXPIRACION = 1800000;
	
	public static String generarTocken(String username, String rol) {
		Algorithm algoritmo = Algorithm.HMAC256(CLAVE_SECRETA);
		long tiempoActual = System.currentTimeMillis();
		Date fechaExpiracion = new Date(tiempoActual + TIEMPO_EXPIRACION);
		String tokenGenerado = JWT.create().withIssuer(EMISOR).withSubject(username)
				.withIssuedAt(new Date(tiempoActual)).withExpiresAt(fechaExpiracion).withClaim("rol", rol)
				.sign(algoritmo);
		return tokenGenerado;
	}
	
	public static DecodedJWT validarTokens(String token) {
		try {
			Algorithm algoritmo = Algorithm.HMAC256(CLAVE_SECRETA);
			JWTVerifier verificador = JWT.require(algoritmo).withIssuer(EMISOR).build();
			DecodedJWT tokenValidado = verificador.verify(token);
			return tokenValidado;
		}catch(Exception e) {
			logger.error("Error al verificar el token!" + e.getMessage());
			return null;
		}
	}
}
