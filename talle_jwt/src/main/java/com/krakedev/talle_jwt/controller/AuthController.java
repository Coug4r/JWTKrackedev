package com.krakedev.talle_jwt.controller;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.krakedev.talle_jwt.JwtUtil;
import com.krakedev.talle_jwt.entidades.Usuario;
import com.krakedev.talle_jwt.repositories.UsuarioRepository;
import com.krakedev.talle_jwt.services.UsuarioService;

@Controller
@RequestMapping("/auth")
public class AuthController {
	private final UsuarioService usurarioService;
	private final UsuarioRepository ususarioRepository;
	
	public AuthController(UsuarioService usurarioService, UsuarioRepository usuarioRepository) {
		this.usurarioService = usurarioService;
		this.ususarioRepository = usuarioRepository;
	}
	@PostMapping("/registrar")
	public ResponseEntity<?> registrar(@RequestBody Usuario usuario){
		try {
			Usuario usuarioNuevo = usurarioService.guardar(usuario);
			return ResponseEntity.status(HttpStatus.CREATED).body(usuarioNuevo);
		}catch(Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error al registrar el usuario!");
		}
	}
	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody Map<String, String> credenciales){
		String username = credenciales.get("username");
		String password = credenciales.get("password");
		
		boolean autenticado = usurarioService.autenticar(username, password);
		if(autenticado) {
			Usuario usuario = ususarioRepository.findByUsername(username).get();
			String token = JwtUtil.generarToken(usuario.getUsername(), usuario.getRol());
			return ResponseEntity.ok(Map.of("token", token));
		}else {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuario o contraseña incorrectos!");
		}
	}
	@GetMapping("/verPerfil")
	public ResponseEntity<?> verPerfil(@RequestHeader(value = "Authorization", required = false) String authHeader){
		if(authHeader == null|| !authHeader.startsWith("Bearer ")) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Acceso denegado debe proveer un token valido en la cabezera Authorization!");
		}
		String token = authHeader.substring(7);
		DecodedJWT datosToken = JwtUtil.validarToken(token);
		if(datosToken == null) {
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
