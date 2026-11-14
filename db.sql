/*
###-
create database webapps;
GRANT ALL PRIVILEGES ON webapps.* TO 'udbwebaps'@'localhost' IDENTIFIED BY 'ku>;k8ND4CN4';
FLUSH PRIVILEGES
*/

/*use webapps;*/

CREATE TABLE Usuario (
    id INT AUTO_INCREMENT PRIMARY KEY,
    uname VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
	/* Se agrego para uso de TOTP */
    totp_secret VARCHAR(64) NULL
)ENGINE=InnoDB;

create table if not exists AccesoToken(
	id_Usuario int primary key, 
	token varchar(250) not null,
	fecha datetime not null
)ENGINE=InnoDB;

create table if not exists Imagen(
	id int AUTO_INCREMENT, 
	name varchar(250) not null,
	ruta text not null,
	id_Usuario int not null,
	PRIMARY KEY (id)
)ENGINE=InnoDB;

ALTER TABLE Usuario
ADD CONSTRAINT U_U
Unique (uname,email); 

ALTER TABLE AccesoToken 
ADD CONSTRAINT FK_AT_U
FOREIGN KEY (id_Usuario) REFERENCES Usuario(ID); 

ALTER TABLE Imagen 
ADD CONSTRAINT FK_I_U
FOREIGN KEY (id_Usuario) REFERENCES Usuario(ID); 
