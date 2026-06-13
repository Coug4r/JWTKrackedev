package com.krakedev.talle_jwt.services;

import java.util.List;
import java.util.Optional;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.stereotype.Service;

import com.krakedev.talle_jwt.entidades.Usuario;
import com.krakedev.talle_jwt.repositories.UsuarioRepository;

@Service
public class UsuarioService {

    private final UsuarioRepository usuarioRepository;

    // Inyección por constructor
    public UsuarioService(UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
    }

    // Guardar usuario
    public Usuario guardar(Usuario usuario) {
    	String contrasenaEncriptada = BCrypt.hashpw(usuario.getPassword(), BCrypt.gensalt());
    	usuario.setPassword(contrasenaEncriptada);
        return usuarioRepository.save(usuario);
    }

    // Listar todos
    public List<Usuario> listarTodos() {
        return usuarioRepository.findAll();
    }

    // Buscar por ID
    public Optional<Usuario> buscarPorId(Integer id) {
        return usuarioRepository.findById(id);
    }

    // Autenticar usuario por username y password
    public boolean autenticar(String username, String password) {
        Optional<Usuario> usuarioOpt = usuarioRepository.findByUsername(username);
        if (usuarioOpt.isPresent()) {
            Usuario usuario = usuarioOpt.get();
            if (BCrypt.checkpw(password, usuario.getPassword())) {
                return true;
            }
        }
        return false;
    }

    // Eliminar usuario
    public void eliminar(Integer id) {
        usuarioRepository.deleteById(id);
    }
}
