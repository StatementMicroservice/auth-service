package com.cbl.statement.security.entity;


import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "Refresh_Token")
public class RefreshToken {
    @Id
    @GeneratedValue
    @Column(name = "Id")
    private Long id;

    @Column(name = "RefreshToken", nullable = false, length = 10000)
    private String refreshToken;

    @Column(name = "Revoked")
    private boolean revoked;

    @ManyToOne
    @JoinColumn(name = "UserId", referencedColumnName = "Id")
    private User user;
}
