package com.krakedev.talle_jwt;

import java.sql.Date;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.krakedev.talle_jwt.services.UsuarioService;


public class JwtUtil {
	private static final Logger logger = LogManager.getLogger(UsuarioService.class);
	
	private static final String CLAVE_SECRETA = "EstaEsUnaClaveSuperSecretaYMuyLarga1234567890!";

	private static final String EMISOR = "KrakeDevBackend";

	private static final long TIEMPO_EXPIRACION = 3600000;

	public static String generarToken(String username, String rol) {
		Algorithm algoritmo = Algorithm.HMAC256(CLAVE_SECRETA);
		long tiempoActual = System.currentTimeMillis();
		Date fechaExpiracion = new Date(tiempoActual + TIEMPO_EXPIRACION);
		String tokenGenerado = JWT.create().withIssuer(EMISOR).withSubject(username)
				.withIssuedAt(new Date(tiempoActual)).withExpiresAt(fechaExpiracion).withClaim("rol", rol)
				.sign(algoritmo);
		return tokenGenerado;
	}

	public static DecodedJWT validarToken(String token) {
		try {
			Algorithm algoritmo = Algorithm.HMAC256(CLAVE_SECRETA);
			JWTVerifier verificador = JWT.require(algoritmo).withIssuer(EMISOR).build();
			DecodedJWT tokenDecodificado = verificador.verify(token);
			return tokenDecodificado;
		}catch(Exception e) {
			logger.error("Error de validacion del Token: "+ e.getMessage());
			return null;
		}
	}
	
	
}
