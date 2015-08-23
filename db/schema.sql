-- MySQL dump 10.13  Distrib 5.6.24, for osx10.8 (x86_64)
--
-- Host: localhost    Database: maltelligence
-- ------------------------------------------------------
-- Server version	5.6.24

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `as_registrar`
--

DROP TABLE IF EXISTS `as_registrar`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `as_registrar` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `registration_date` date DEFAULT NULL,
  `ranking` int(11) DEFAULT NULL,
  `ipv4` int(11) DEFAULT NULL,
  `ipv4_pre` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=69970 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `autonomous_system`
--

DROP TABLE IF EXISTS `autonomous_system`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `autonomous_system` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `asn` int(10) unsigned NOT NULL,
  `monitoring_count` int(10) unsigned DEFAULT '0',
  `monitoring_code` tinyint(2) unsigned DEFAULT '1',
  `country_id` int(10) unsigned DEFAULT NULL,
  `registrar_id` int(10) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`,`asn`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  UNIQUE KEY `asn_UNIQUE` (`asn`),
  KEY `registrar_id_idx` (`registrar_id`),
  KEY `country_id_idx` (`country_id`),
  CONSTRAINT `country_id` FOREIGN KEY (`country_id`) REFERENCES `country` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  CONSTRAINT `registrar_id` FOREIGN KEY (`registrar_id`) REFERENCES `as_registrar` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=70653 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `av_classification`
--

DROP TABLE IF EXISTS `av_classification`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `av_classification` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `av_vendor` varchar(255) DEFAULT NULL,
  `detection_name` varchar(255) DEFAULT NULL,
  `sample_id` bigint(20) unsigned DEFAULT NULL,
  `metadata_id` bigint(20) unsigned DEFAULT NULL,
  `reference` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `sample_id_idx` (`sample_id`),
  KEY `metadata_id_idx` (`metadata_id`),
  CONSTRAINT `metadata_id3` FOREIGN KEY (`metadata_id`) REFERENCES `metadata` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  CONSTRAINT `sample_id2` FOREIGN KEY (`sample_id`) REFERENCES `malware_sample` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `c2`
--

DROP TABLE IF EXISTS `c2`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `c2` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `dns_id` bigint(20) unsigned DEFAULT NULL,
  `sample_id` bigint(20) unsigned DEFAULT NULL,
  `detection_date` date DEFAULT NULL,
  `source` varchar(255) DEFAULT NULL,
  `monitoring_code` tinyint(2) unsigned DEFAULT '1',
  `monitoring_count` int(10) unsigned DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `dns_id_idx` (`dns_id`),
  KEY `sample_id_idx` (`sample_id`),
  CONSTRAINT `dns_id` FOREIGN KEY (`dns_id`) REFERENCES `dns` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  CONSTRAINT `sample_id` FOREIGN KEY (`sample_id`) REFERENCES `malware_sample` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `case_artefacts`
--

DROP TABLE IF EXISTS `case_artefacts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `case_artefacts` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `ip_id` bigint(20) unsigned NOT NULL,
  `domain_id` bigint(20) unsigned NOT NULL,
  `sample_id` bigint(20) unsigned DEFAULT NULL,
  `case_id` int(10) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`,`ip_id`,`domain_id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `ip_id_idx` (`ip_id`),
  KEY `domain_id_idx` (`domain_id`),
  KEY `sample_id_idx` (`sample_id`),
  KEY `case_id_idx` (`case_id`),
  CONSTRAINT `case_id` FOREIGN KEY (`case_id`) REFERENCES `cases` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  CONSTRAINT `domain_idx` FOREIGN KEY (`domain_id`) REFERENCES `domain` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  CONSTRAINT `ip_idx` FOREIGN KEY (`ip_id`) REFERENCES `ip` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  CONSTRAINT `sample_idx` FOREIGN KEY (`sample_id`) REFERENCES `malware_sample` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cases`
--

DROP TABLE IF EXISTS `cases`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `cases` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `description` text,
  `case_date` date DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `communicate_with`
--

DROP TABLE IF EXISTS `communicate_with`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `communicate_with` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `dns_id` bigint(20) unsigned NOT NULL,
  `detection_date` date DEFAULT NULL,
  `sha256` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  UNIQUE KEY `sha256_UNIQUE` (`sha256`),
  KEY `dns_id7` (`dns_id`),
  CONSTRAINT `dns_id7` FOREIGN KEY (`dns_id`) REFERENCES `dns` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `country`
--

DROP TABLE IF EXISTS `country`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `country` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `country` varchar(5) NOT NULL,
  `country_number` varchar(25) DEFAULT NULL,
  `country_name` varchar(255) DEFAULT NULL,
  `population` int(10) unsigned DEFAULT NULL,
  `area` int(10) unsigned DEFAULT NULL,
  `GDP` float DEFAULT NULL,
  `monitoring_code` tinyint(2) unsigned DEFAULT '1',
  PRIMARY KEY (`country`),
  UNIQUE KEY `idcountry_UNIQUE` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=249 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `dns`
--

DROP TABLE IF EXISTS `dns`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `dns` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `ip_id` bigint(20) unsigned NOT NULL,
  `domain_id` bigint(20) unsigned NOT NULL,
  `source` varchar(255) DEFAULT NULL,
  `status` tinyint(3) unsigned DEFAULT NULL,
  `confidence` tinyint(3) unsigned DEFAULT NULL,
  `tlp_id` tinyint(3) unsigned DEFAULT NULL,
  `metatdata_id` bigint(20) unsigned DEFAULT NULL,
  `scan_date` date DEFAULT NULL,
  PRIMARY KEY (`id`,`ip_id`,`domain_id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `id_idx` (`ip_id`),
  KEY `id_idx1` (`domain_id`),
  KEY `metadata_id_idx` (`metatdata_id`),
  KEY `tlp_id_idx` (`tlp_id`),
  CONSTRAINT `domain_id` FOREIGN KEY (`domain_id`) REFERENCES `domain` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  CONSTRAINT `ip_id` FOREIGN KEY (`ip_id`) REFERENCES `ip` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  CONSTRAINT `metadata_id` FOREIGN KEY (`metatdata_id`) REFERENCES `metadata` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT `tlp_id3` FOREIGN KEY (`tlp_id`) REFERENCES `tlp` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `domain`
--

DROP TABLE IF EXISTS `domain`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `domain` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `hostname` varchar(255) DEFAULT NULL,
  `secondLD` varchar(255) DEFAULT NULL,
  `domain` varchar(255) NOT NULL,
  `source` varchar(255) DEFAULT NULL,
  `tlp_id` tinyint(3) unsigned DEFAULT NULL,
  `monitoring_code` tinyint(2) unsigned DEFAULT '0',
  `monitoring_count` int(10) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`,`domain`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `tlp_id_idx` (`tlp_id`),
  CONSTRAINT `tlp_id2` FOREIGN KEY (`tlp_id`) REFERENCES `tlp` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `geoip`
--

DROP TABLE IF EXISTS `geoip`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `geoip` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `country_code` varchar(45) DEFAULT NULL,
  `country_name` varchar(255) DEFAULT NULL,
  `country_name_CN` varchar(255) DEFAULT NULL,
  `city_name` varchar(255) DEFAULT NULL,
  `latitude` float DEFAULT NULL,
  `longitude` float DEFAULT NULL,
  `is_anonymous` tinyint(1) DEFAULT NULL,
  `is_vpn` tinyint(1) DEFAULT NULL,
  `is_public_proxy` tinyint(1) DEFAULT NULL,
  `is_hosting_provider` tinyint(1) DEFAULT NULL,
  `is_tor_exit_node` tinyint(1) DEFAULT NULL,
  `connection_type` varchar(45) DEFAULT NULL,
  `ip_id` bigint(20) unsigned NOT NULL,
  `scan_date` date DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `GeoIP_ip_idx` (`ip_id`),
  CONSTRAINT `GeoIP_ip` FOREIGN KEY (`ip_id`) REFERENCES `ip` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `htmls`
--

DROP TABLE IF EXISTS `htmls`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `htmls` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `domain_id` bigint(20) unsigned NOT NULL,
  `server` varchar(45) DEFAULT NULL,
  `modified_date` date DEFAULT NULL,
  `location` varchar(45) DEFAULT NULL,
  `encoding` varchar(45) DEFAULT NULL,
  `no_of_scripts` int(11) DEFAULT NULL,
  `no_of_links` int(11) DEFAULT NULL,
  `no_of_images` int(11) DEFAULT NULL,
  `no_of_iframes` int(11) DEFAULT NULL,
  `html_page` mediumtext,
  `scan_date` date DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `domain_id` (`domain_id`),
  CONSTRAINT `htmls_ibfk_1` FOREIGN KEY (`domain_id`) REFERENCES `domain` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `iframes`
--

DROP TABLE IF EXISTS `iframes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iframes` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `htmls_id` int(10) unsigned NOT NULL,
  `src` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `fk_iframes_htmls1_idx` (`htmls_id`),
  CONSTRAINT `htmls_id3` FOREIGN KEY (`htmls_id`) REFERENCES `htmls` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `images`
--

DROP TABLE IF EXISTS `images`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `images` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `htmls_id` int(10) unsigned NOT NULL,
  `src` varchar(255) DEFAULT NULL,
  `alt` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `fk_images_htmls1_idx` (`htmls_id`),
  CONSTRAINT `htmls_id2` FOREIGN KEY (`htmls_id`) REFERENCES `htmls` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ioc`
--

DROP TABLE IF EXISTS `ioc`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ioc` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `patterns` text,
  `sample_id` bigint(20) unsigned DEFAULT NULL,
  `source` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `sample_id_idx` (`sample_id`),
  CONSTRAINT `sample_id3` FOREIGN KEY (`sample_id`) REFERENCES `malware_sample` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ip`
--

DROP TABLE IF EXISTS `ip`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ip` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `ip` varchar(15) DEFAULT NULL,
  `source` varchar(255) DEFAULT NULL,
  `tlp_id` tinyint(3) unsigned DEFAULT NULL,
  `asn_id` int(10) unsigned DEFAULT NULL,
  `monitoring_code` tinyint(2) unsigned DEFAULT '0',
  `monitoring_count` int(10) unsigned DEFAULT NULL,
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `asn_id_idx` (`asn_id`),
  KEY `tlp_id_idx` (`tlp_id`),
  CONSTRAINT `asn_id` FOREIGN KEY (`asn_id`) REFERENCES `autonomous_system` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  CONSTRAINT `tlp_id` FOREIGN KEY (`tlp_id`) REFERENCES `tlp` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `links`
--

DROP TABLE IF EXISTS `links`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `links` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `htmls_id` int(10) unsigned NOT NULL,
  `url` varchar(512) DEFAULT NULL,
  `text` text,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `fk_links_htmls1_idx` (`htmls_id`),
  CONSTRAINT `htmls_id1` FOREIGN KEY (`htmls_id`) REFERENCES `htmls` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `malware_sample`
--

DROP TABLE IF EXISTS `malware_sample`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `malware_sample` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `md5` char(32) DEFAULT NULL,
  `sha1` char(40) DEFAULT NULL,
  `sha256` char(64) DEFAULT NULL,
  `source` mediumtext,
  `metadata` bigint(20) unsigned DEFAULT NULL,
  `type` varchar(255) DEFAULT NULL,
  `pcap` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  UNIQUE KEY `md5_UNIQUE` (`md5`),
  UNIQUE KEY `sha1_UNIQUE` (`sha1`),
  UNIQUE KEY `sha256_UNIQUE` (`sha256`),
  KEY `metadata_id_idx` (`metadata`),
  CONSTRAINT `metadata_id2` FOREIGN KEY (`metadata`) REFERENCES `metadata` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `metadata`
--

DROP TABLE IF EXISTS `metadata`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `metadata` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `data` mediumtext NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  FULLTEXT KEY `data` (`data`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scan_detection`
--

DROP TABLE IF EXISTS `scan_detection`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `scan_detection` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `postives` tinyint(3) unsigned DEFAULT NULL,
  `source` varchar(255) DEFAULT NULL,
  `detection_date` date DEFAULT NULL,
  `sample_id` bigint(20) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `sample_id_idx` (`sample_id`),
  CONSTRAINT `sample_id4` FOREIGN KEY (`sample_id`) REFERENCES `malware_sample` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scripts`
--

DROP TABLE IF EXISTS `scripts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `scripts` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `htmls_id` int(10) unsigned NOT NULL,
  `type` varchar(45) DEFAULT NULL,
  `src` text,
  `content` text,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `fk_scripts_htmls1_idx` (`htmls_id`),
  CONSTRAINT `htmls_id` FOREIGN KEY (`htmls_id`) REFERENCES `htmls` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `subnet`
--

DROP TABLE IF EXISTS `subnet`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `subnet` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `subnet` varchar(25) NOT NULL,
  `asn_id` int(10) unsigned NOT NULL,
  `country` char(5) DEFAULT NULL,
  `description` mediumtext,
  `scan_date` date DEFAULT NULL,
  `monitoring_code` tinyint(2) unsigned DEFAULT '0',
  `monitoring_count` int(10) unsigned DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  UNIQUE KEY `subnet_UNIQUE` (`subnet`),
  KEY `asn_id_idx` (`asn_id`),
  CONSTRAINT `asn_id2` FOREIGN KEY (`asn_id`) REFERENCES `autonomous_system` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=219503 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tlp`
--

DROP TABLE IF EXISTS `tlp`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tlp` (
  `id` tinyint(3) unsigned NOT NULL AUTO_INCREMENT,
  `colour` varchar(45) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  UNIQUE KEY `colour_UNIQUE` (`colour`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `urls`
--

DROP TABLE IF EXISTS `urls`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `urls` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `dns_id` bigint(20) unsigned NOT NULL,
  `detection_date` date DEFAULT NULL,
  `url` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  UNIQUE KEY `url_UNIQUE` (`url`),
  KEY `dns_id6_idx` (`dns_id`),
  CONSTRAINT `dns_id6` FOREIGN KEY (`dns_id`) REFERENCES `dns` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `whois`
--

DROP TABLE IF EXISTS `whois`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `whois` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `creation_date` date DEFAULT NULL,
  `last_update_date` date DEFAULT NULL,
  `registrar` varchar(255) DEFAULT NULL,
  `registrant_name` varchar(255) NOT NULL DEFAULT '',
  `registrant_email` varchar(255) NOT NULL DEFAULT '',
  `name_servers` mediumtext,
  `telephone` varchar(45) DEFAULT NULL,
  `last_scan_date` date NOT NULL,
  `domain_id` bigint(20) unsigned NOT NULL,
  `monitoring_code` tinyint(2) unsigned DEFAULT '0',
  `monitoring_count` int(10) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`,`registrant_name`,`registrant_email`,`last_scan_date`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `fk_whois_domain1_idx` (`domain_id`),
  CONSTRAINT `domain_id2` FOREIGN KEY (`domain_id`) REFERENCES `domain` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2015-08-14 19:30:51
