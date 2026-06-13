package com.krakedev.jwt.controllers;

import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.repositories.UsuarioRepository;
import com.krakedev.jwt.services.UsuarioService;
import com.krakedev.jwt.utils.JWUtil;

@Controller
@RequestMapping("/refugio")
public class AuthController {
	private static final Logger logger = LogManager.getLogger(UsuarioService.class);
	private final UsuarioService ususarioService;
	private final UsuarioRepository usuarioRepository;
	public AuthController(UsuarioService ususarioService, UsuarioRepository usuarioRepository) {
		this.ususarioService = ususarioService;
		this.usuarioRepository = usuarioRepository;
	}
	
	@PostMapping("/registrar")
	public ResponseEntity<?> registrar(@RequestBody Usuario usuario){
		try {
			Usuario usuarioNuevo = ususarioService.guardar(usuario);
			return ResponseEntity.status(HttpStatus.CREATED).body(usuarioNuevo);
		}catch(Exception e) {
			logger.error("Error al registrar Usuario!"+e.getMessage());
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error al registrar usuario!");
		}
	}
	
	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody Map<String, String> credenciales){
		String username = credenciales.get("username");
		String password = credenciales.get("password");
		
		boolean autenticado = ususarioService.autenticar(username, password);
		if(autenticado) {
			Usuario usuario = usuarioRepository.findByUsername(username).get();
			String token = JWUtil.generarTocken(usuario.getUsername(), usuario.getRol());
			return ResponseEntity.ok(Map.of("token: ",token));
		}
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuario o contraseña incorrectos!");
	}
	
	@GetMapping("/perfil")
	public ResponseEntity<?> perfil(@RequestHeader(value="Authorization", required = false) String authHeader){
		if(authHeader == null) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Acceso denegado debe proveerun token de autorizacion valido!");
		}
		String token = authHeader.substring(7);
		DecodedJWT datosToken = JWUtil.validarTokens(token);
		if(datosToken==null) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Acceso denegado token invalido o Expirado!");
		}
		String usuario = datosToken.getSubject();
		String rol = datosToken.getClaim("rol").asString();
		return ResponseEntity.ok(Map.of(
				"Mensaje", "Bienvenido sistema protegido por JWT", 
				"Usuario", usuario,
				"Rol", rol,
				"Estatus", "Autenticado correctamente!"
				));
	}
}
