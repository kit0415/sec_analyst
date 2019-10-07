-- phpMyAdmin SQL Dump
-- version 4.7.4
-- https://www.phpmyadmin.net/
--
-- 主機: 127.0.0.1
-- 產生時間： 
-- 伺服器版本: 10.1.28-MariaDB
-- PHP 版本： 7.1.11

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET AUTOCOMMIT = 0;
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- 資料庫： `securityanalytic`
--

-- --------------------------------------------------------

--
-- 資料表結構 `logcases`
--

CREATE TABLE `logcases` (
  `caseID` int(11) NOT NULL,
  `CaseName` varchar(255) NOT NULL,
  `dateUploaded` datetime NOT NULL,
  `filepath` varchar(1000) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- 資料表的匯出資料 `logcases`
--

INSERT INTO `logcases` (`caseID`, `CaseName`, `dateUploaded`, `filepath`) VALUES
(1, 'sd', '2019-10-07 00:00:00', 'dsa'),
(2, 'testcase', '2019-10-07 10:00:00', 'data/log.zip');

--
-- 已匯出資料表的索引
--

--
-- 資料表索引 `logcases`
--
ALTER TABLE `logcases`
  ADD PRIMARY KEY (`caseID`);

--
-- 在匯出的資料表使用 AUTO_INCREMENT
--

--
-- 使用資料表 AUTO_INCREMENT `logcases`
--
ALTER TABLE `logcases`
  MODIFY `caseID` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
