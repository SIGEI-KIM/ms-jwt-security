package com.sigei.ms_jwt_security.model.request;

import com.sigei.ms_jwt_security.dblayer.entity.Role;
import lombok.Data;

@Data
public class UserRequest {
    private String firstName;
    private String lastName;
    private String username;
    private String password;
    private Role role;
}
