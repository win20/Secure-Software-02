-- MariaDB dump 10.19  Distrib 10.4.24-MariaDB, for Win64 (AMD64)
--
-- Host: localhost    Database: nodejs-login
-- ------------------------------------------------------
-- Server version	10.4.24-MariaDB

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `users_test`
--

DROP TABLE IF EXISTS `users_test`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users_test` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `secret_ascii` varchar(255) NOT NULL,
  `secret_hex` varchar(255) NOT NULL,
  `secret_base32` varchar(255) NOT NULL,
  `secret_otpauth_url` varchar(255) NOT NULL,
  `is_auth_verified` tinyint(1) NOT NULL DEFAULT 0,
  `is_email_otp_verified` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=21 DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users_test`
--

LOCK TABLES `users_test` WRITE;
/*!40000 ALTER TABLE `users_test` DISABLE KEYS */;
INSERT INTO `users_test` VALUES (17,'Win','win.barua.work@gmail.com','$2a$08$3uXWDp3x4wAlkOCYf0M2Jutfyq3fGfoiTLxwXVWR7NnVn16F8owUa','])TfO>8D2ES#bbddhJyQ7r&UREE/ryNE','5d2954664f3e38443245532362626464684a7951377226555245452f72794e45','LUUVIZSPHY4EIMSFKMRWEYTEMRUEU6KRG5ZCMVKSIVCS64TZJZCQ','otpauth://totp/SecretKey?secret=LUUVIZSPHY4EIMSFKMRWEYTEMRUEU6KRG5ZCMVKSIVCS64TZJZCQ',0,0),(18,'Win','win.barua2@gmail.com','$2a$08$pgsHN/iP3OOsb5GMEcaC7epAe9j.UBvXj0yanLZeoO9qn0i/u717a','','','','',0,0),(20,'Win','jsmith@gmail.com','$2a$08$W8B4So2CULNIKWf9pSoTl.wmUynWcpWUDxwMGQIShKbin2luh4zvK','','','','',0,0);
/*!40000 ALTER TABLE `users_test` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2022-05-03 17:21:39
