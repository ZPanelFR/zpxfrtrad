<?php
if (!isset($Langue)) {
$Langue = explode(',',$_SERVER['HTTP_ACCEPT_LANGUAGE']);
$Langue = strtolower(substr(chop($Langue[0]),0,2));
}
if (file_exists("lang/login.".$Langue.".php")) {
include("lang/login.".$Langue.".php");
} else {
include("lang/login.en.php");
}


/**
* @copyright 2014-2015 Sentora Project (http://www.sentora.org/)
* Sentora is a GPL fork of the ZPanel Project whose original header follows:
*
* The web gui initiation script.
* @package zpanelx
* @subpackage core
* @author Bobby Allen (ballen@bobbyallen.me)
* @copyright ZPanel Project (http://www.zpanelcp.com/)
* @link http://www.zpanelcp.com/
* @license GPL (http://www.gnu.org/licenses/gpl.html)
*/
global $controller, $zdbh, $zlo;
$controller = new runtime_controller();
runtime_hook::Execute('OnBoot');
$zlo->method = ctrl_options::GetSystemOption('logmode');
if ($zlo->hasInfo()) {
$zlo->writeLog();
$zlo->reset();
}
if (isset($_GET['logout'])) {
runtime_hook::Execute('OnLogout');
ctrl_auth::KillSession();
ctrl_auth::KillCookies();
header("location: ./?loggedout");
exit;
}
if (isset($_GET['returnsession'])) {
if (isset($_SESSION['ruid'])) {
ctrl_auth::SetUserSession($_SESSION['ruid'], runtime_sessionsecurity::getSessionSecurityEnabled());
$_SESSION['ruid'] = null;
}
header("location: ./");
exit;
}

if (file_exists("lang/".$Langue.".php")) {
include("lang/".$Langue.".php");
} else {
include("lang/en.php");
}


if (isset($_POST['inConfEmail'])) {
runtime_csfr::Protect();
$sql = $zdbh->prepare("SELECT ac_id_pk FROM x_accounts WHERE ac_email_vc = :email AND ac_resethash_tx = :resetkey AND ac_resethash_tx IS NOT NULL AND ac_deleted_ts IS NULL");
$sql->bindParam(':email', $_POST['inConfEmail']);
$sql->bindParam(':resetkey', $_GET['resetkey']);
$sql->execute();
$result = $sql->fetch();
$crypto = new runtime_hash;
$crypto->SetPassword($_POST['inNewPass']);
$randomsalt = $crypto->RandomSalt();
$crypto->SetSalt($randomsalt);
$secure_password = $crypto->CryptParts($crypto->Crypt())->Hash;
if ($result) {
$sql = $zdbh->prepare("UPDATE x_accounts SET ac_resethash_tx = '', ac_pass_vc = :password, ac_passsalt_vc = :salt WHERE ac_id_pk = :uid");
$sql->bindParam(':password', $secure_password);
$sql->bindParam(':salt', $randomsalt);
$sql->bindParam(':uid', $result['ac_id_pk']);
$sql->execute();
runtime_hook::Execute('OnSuccessfulPasswordReset');
} else {
runtime_hook::Execute('OnFailedPasswordReset');
}
header("location: ./?passwordreset");
exit();
}
if (isset($_POST['inUsername'])) {
if (ctrl_options::GetSystemOption('login_csfr') == 'false')
runtime_csfr::Protect();
$rememberdetails = isset($_POST['inRemember']);
$inSessionSecuirty = isset($_POST['inSessionSecuirty']);
$sql = $zdbh->prepare("SELECT ac_passsalt_vc FROM x_accounts WHERE ac_user_vc = :username AND ac_deleted_ts IS NULL");
$sql->bindParam(':username', $_POST['inUsername']);
$sql->execute();
$result = $sql->fetch();
$crypto = new runtime_hash;
$crypto->SetPassword($_POST['inPassword']);
$crypto->SetSalt($result['ac_passsalt_vc']);
$secure_password = $crypto->CryptParts($crypto->Crypt())->Hash;
if (!ctrl_auth::Authenticate($_POST['inUsername'], $secure_password, $rememberdetails, false, $inSessionSecuirty)) {
header("location: ./?invalidlogin");
exit();
}
}
if (isset($_COOKIE['zUser'])) {
if (isset($_COOKIE['zSec'])) {
if ($_COOKIE['zSec'] == false) {
$secure = false;
} else {
$secure = true;
}
} else {
$secure = true;
}
ctrl_auth::Authenticate($_COOKIE['zUser'], $_COOKIE['zPass'], false, true, $secure);
}
if (!isset($_SESSION['zpuid'])) {
ctrl_auth::RequireUser();
}
runtime_hook::Execute('OnBeforeControllerInit');
$controller->Init();
ui_templateparser::Generate("etc/styles/" . ui_template::GetUserTemplate());
?>
