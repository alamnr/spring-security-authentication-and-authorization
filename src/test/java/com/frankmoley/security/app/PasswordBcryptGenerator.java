package com.frankmoley.security.app;

import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class PasswordBcryptGenerator {

    @Test
    public void generateBcrypt(){
        String pass_1 = "password";
        String pass_2 = "foobar";
        String hashPass_1 = null;
        String hashPass_2 = null;

        int i=0;
        while(i<11){
            BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
            hashPass_1 = passwordEncoder.encode(pass_1);
            hashPass_2 = passwordEncoder.encode(pass_2);
            i++;
        }


        System.out.println(hashPass_1);

        System.out.println(hashPass_2);

        Assertions.assertThat(hashPass_1).isNotNull();
        Assertions.assertThat(hashPass_2).isNotNull();
        Assertions.assertThat(i).isEqualTo(11);




    }

}
