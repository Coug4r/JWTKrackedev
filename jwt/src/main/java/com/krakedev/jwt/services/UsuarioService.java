package com.krakedev.jwt.services;

import java.util.Optional;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.stereotype.Service;

import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.repositories.UsuarioRepository;

@Service
public class UsuarioService {

    private final UsuarioRepository usuarioRepository;

    // Inyección por constructor
    public UsuarioService(UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
    }

    // Guardar usuario
    public Usuario guardar(Usuario usuario) {
    	String contrasena = BCrypt.hashpw(usuario.getPassword(), BCrypt.gensalt());
    	usuario.setPassword(contrasena);
        return usuarioRepository.save(usuario);
    }

    // Autenticar usuario por username y password
    public boolean autenticar(String username, String password) {
        Optional<Usuario> usuarioOpt = usuarioRepository.findByUsername(username);
        if (usuarioOpt.isPresent()) {
            Usuario usuario = usuarioOpt.get();
            if(BCrypt.checkpw(password, usuario.getPassword())) {
            	return true;
            }
        }
        return false;
    }
}
