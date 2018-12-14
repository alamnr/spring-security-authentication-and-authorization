package com.frankmoley.security.app.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class LandonUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;
    private final AuthGroupRepository  authGroupRepository;

    public LandonUserDetailService(UserRepository userRepository, AuthGroupRepository authGroupRepository){
        this.userRepository = userRepository;
        this.authGroupRepository = authGroupRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(userName);
        if(null==user){
            throw new UsernameNotFoundException("cannot find user name: "+ userName);
        }
        List<AuthGroup> authGroups = authGroupRepository.findByUsername(userName);
        return new LandonUserPrincipal(user, authGroups);
    }
}
