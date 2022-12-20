<!doctype html>
<?php

	header("X-Frame-Options: DENY");
	header("Referrer-Policy: origin-when-cross-origin");
	header("X-XSS-Protection: 1");
	header("X-Content-Type-Options: nosniff");
	header
	(
		"Content-Security-Policy: "
		."default-src 'none'; "
		."style-src 'unsafe-inline'; "
		."block-all-mixed-content "
	);

	const title = 'Secure Note';
	const description = 'This is a self-destructing, secure note';
	const meta_image = 'vault.png';

	const default_lifetime_hours = 42;
	const default_number_of_views = 3;

	const ban_hours = 42;
	const failed_attempts_to_ban = 9;

	const default_passphrase = 'nothing';

	$failed_attempts = 0;

	$application_path = $_SERVER['DOCUMENT_ROOT'];
	$password_file    = $_SERVER['DOCUMENT_ROOT'].'/.htpasswd';


?>
<html lang=en>

	<head prefix="og: http://ogp.me/ns# fb: http://ogp.me/ns/fb# product: http://ogp.me/ns/product#">


		<meta
			charset=utf-8
		>
		<meta
			name=viewport
			content="width=device-width,initial-scale=1,user-scalable=yes"
		>
		<meta
			name=robots
			content="noindex, nofollow"
		>
		<meta
			property="og:title"
			content="<?= title ?>"
		>
		<meta
			property="og:description"
			content="<?= description ?>"
		>
		<meta
			property="og:image"
			content="https://<?= $_SERVER['SERVER_NAME'].'/'.meta_image ?>"
		>
		<link rel="icon" type="image/x-icon" href="/favicon.ico" >

		<title><?= title ?></title>


		<style>
			*
			{
				box-sizing: border-box;
			}
			body
			{
				background-color: #2c3e50;
				color: #d3d3d3;
				font-family: monospace;
			}
			body,
			input,
			textarea
			{
				font-size: 20px;
			}
			main
			{
				max-width: 570px;
				margin: 50px auto 70px auto;
			}
			h1
			{
				text-align: center;
				margin: 0 0 45px 0;
			}
			h1 a
			{
				color: #fff4;
				text-decoration: none;
			}
			#message-label
			{
				margin: 32px 0 12px 0;
				display: inline-block;
			}
			textarea
			{
				width: 100%;
				height: 200px;
				padding: 9px 14px;
			}
			br,
			label
			{
				clear: both;
			}
			input
			{
				width: 260px;
				padding: 4px 12px;
				float: right;
			}
			input,
			textarea
			{
				background-color: #34495e;
				border: 1px solid #ffffff1d;
				margin: 4px 0;
				color: #fbc531;
				border-radius: 4px;
			}
			input[type=submit]
			{
				width: auto;
				min-width: 85px;
				margin: 25px 0 0 0;
				background-color: #fbc531;
				color: #2c3e50;
				font-weight: bold;
			}
			input::-webkit-outer-spin-button,
			input::-webkit-inner-spin-button
			{
				-webkit-appearance: none;
				margin: 0;
			}
			input[type=number]
			{
				-moz-appearance: textfield;
			}
			a
			{
				color: #fbc531;
			}
			.error
			{
				background-color: #d63031;
				color: #fff;
				padding: 3px 6px;
				text-align: center;
			}
			.mandatory
			{
				color: #ea8685;
			}
			.save-warning
			{
				padding: 6px 12px;
				background-color: #82589F;
				color: white;
				border-radius: 9px;
			}
			.last_show
			{
				background-color: #eb4d4b;
				color: white;
			}
			#show-message input
			{
				float: none;
			}
			footer
			{
				color: #fff3;
				margin-top: 80px;
				font-size: 15px;
				text-align: center;
			}
			#cleanup
			{
				color: #fff2;
				margin: 30px 0 0 0;
			}
			@media only screen and (max-width: 600px)
			{
				body
				{
					padding: 0 15px 25px 15px;
				}
				input
				{
					float: none;
					width: 100%;
					margin-bottom: 25px;
				}
				label
				{
					display: inline-block;
					margin-bottom: 4px;
				}
			}
		</style>

	</head>


	<body>
		<main>
		<h1><a href=/><?= title ?></a></h1>
			<?php

				if (is_banned())
					echo "<p class=error>Your access is temporarily blocked!</p>";

				elseif ( ($_POST['task'] ?? '') === 'set_password' )
					save_submitted_master_password();

				elseif ( empty($_POST) && empty($_GET) && empty($_SERVER['QUERY_STRING']) )
				{
					if (!file_exists('./.htpasswd'))
						set_master_password();
					else
						compose_message();
				}

				elseif ( ($_POST['task'] ?? '') === 'save' )
					save_message();

				elseif ( isset($_POST['message']) )
					show_message();

				elseif ( !empty($_SERVER['QUERY_STRING']) )
					get_confirmation_to_show_message();
			?>
		</main>
		<footer>Powered by S4Notes</footer>
	</body>

</html>

<?php



function compose_message($error = '') // -----------------------------------------------------
{
	if ($error !== '')
		echo "<p class=error>ERROR: $error</p><br>";

	$password    = $_POST['master_password'] ?? '';
	$hours       = $_POST['hours'] ?? default_lifetime_hours;
	$views       = $_POST['views'] ?? default_number_of_views;
	$passphrase  = $_POST['passphrase'] ?? '';
	$passphrase2 = $_POST['passphrase2'] ?? '';
	$url         = $_POST['url'] ?? '';
	$message     = $_POST['message'] ?? '';

	$mandatory = '<span class=mandatory>*</span>';

	echo
		<<<html
			<form method=POST >
				<input type=hidden name=task value=save >
				<label for=fl_master_password>Your master password{$mandatory}:</label>
				<input
					type=password 
					name=master_password
					id=fl_master_password
					value="$password"
					required
					autofocus
				>
				<br>
				<label for=fl_hours>Lifetime (hours){$mandatory}:</label>
				<input
					type=number
					name=hours
					name=fl_hours
					value=$hours
					required
				>
				<br>
				<label for=fl_views>Number of views{$mandatory}:</label>
				<input
					type=number
					name=views
					name=fl_views
					value=$views
					required
				>
				<br>
				<label for=fl_passphrase>Encryption passphrase:</label>
				<input
					type=password
					name=passphrase
					id=fl_passphrase
					value="$passphrase"
				>
				<br>
				<label for=fl_passphrase2>Repeat passphrase:</label>
				<input
					type=password
					name=passphrase2
					id=fl_passphrase2
					value="$passphrase2"
				>
				<br>
				<label for=fl_url>Custom URL:</label>
				<input
					type=text
					name=url
					id=fl_url
					value="{$url}"
				>
				<br>
				<label for=fl_message id=message-label>Message{$mandatory}:</label>
				<br>
				<textarea name=message id=fl_message required>$message</textarea>

				<input type=submit value=Save >
			</form>
		html
	;
}



function sanitize_filename($name) // ---------------------------------------------------------
{
	return
		str_replace
		(
			' '
			,'-'
			,mb_ereg_replace
			(
				"([\.]{2,})"
				,''
				,mb_ereg_replace
				(
					"([^\w\s\d\-_])"
					,''
					,trim($name)
				)
			)
		)
	;
}



function save_message() // -------------------------------------------------------------------
{
	global $password_file;
	$password_hash = file_get_contents($password_file);

	if ($password_hash === false)
	{
		echo "<p class=error>ERROR! Can't get the master password!</p>";
		return;
	}

	if (!password_verify(($_POST['master_password'] ?? ''), $password_hash))
	{
		$_POST['master_password'] = '';
		log_failed_attempt();
		compose_message('Incorrect master password!');
		return;
	}


	// unbanning because they've entered the correct master password
	unban();

	if (trim($_POST['passphrase'] ?? '') !== trim($_POST['passphrase2'] ?? ''))
	{
		compose_message('The two passphrases don\'t match!');
		return;
	}

	if (trim($_POST['message'] ?? '') === '')
	{
		compose_message('Missing the message!');
		return;
	}


	// OK, everything is fine.

	$data['has_passphrase']    = (trim($_POST['passphrase']) != '');
	$data['custom_passphrase'] = ( $data['has_passphrase'] ? $_POST['passphrase'] : default_passphrase );
	$data['expiry']            = strtotime('now +'.($_POST['hours'] ?? default_hours).' hour');
	$data['remaining']         = $_POST['views'] ?? default_number_of_views;
	$data['message']           = $_POST['message'] ?? '';



	// Let's set the file name:

	$url = trim($_POST['url'] ?? '');

	if (strlen($url)>1 && ($url[0]=='>' || $url[0]=='<'))
	{
		$code = substr($data['code'],1);
		$md = strlen($code) % 3;
		$data['code'] = base64_encode($code.($md==2 ? ' ' : '').($md==1 ? '  ' : ''));
	}
	else
	{
		$data['code'] = sanitize_filename($url);

		if ($data['code'] === '')
			$data['code'] = md5(time());
	}


	// Saving the message

	$data['filename'] = $_SERVER['DOCUMENT_ROOT'].'/message-'.$data['code'].'.php';

	$result = save_message_file($data);

	if ($result === false)
		echo "<p class=error>ERROR! Couldn't save the message.</p>";
	else
		echo
			"<p>"
			."Link to the message:"
			."</p>"
			."<textarea readonly autofocus >"
			."https://"
			.$_SERVER['SERVER_NAME']
			."/?"
			.$data['code']
			."</textarea>"
		;

	clean_up_expired_messages();
}



function save_message_file($data) // ---------------------------------------------------------
{
	if ($data['remaining']<1 || $data['expiry']<time())
	{
		if (file_exists($data['filename']))
			unlink($data['filename']);
		return;
	}

	$result =
		file_put_contents
		(
			$data['filename']
			,"<?php die('Access Denied!'); ?>\n"
			.'has_passphrase: '
			.($data['has_passphrase'] ? 'YES' : 'NO')
			."\n"
			.'expiry: '
			.$data['expiry']
			."\n"
			.'remaining: '
			.$data['remaining']
			."\n"
			.'message: '
			.openssl_encrypt
			(
				'encrypted'.$data['message']
				,'aes-256-ofb'
				,$data['custom_passphrase']
				,0
				,substr($data['filename'].$_SERVER['SERVER_NAME'],0,16)
			)
			."\n"
		)
	;

	chmod($data['filename'],0600);
	return $result;
}



function show_message() // -------------------------------------------------------------------
{
	$filename = $_SERVER['DOCUMENT_ROOT'].'/message-'.$_SERVER['QUERY_STRING'].'.php';
	$data = get_message_data($filename, $_POST['passphrase'] ?? default_passphrase, false);

	if ($data=='no_message')
	{
		// counts for banning to avoid bruce forcing to find the links.
		log_failed_attempt();
		echo "<p class=error>There's no such message or it has expired.</p>";
		return;
	}
	elseif ($data=='wrong_passphrase')
	{
		log_failed_attempt();
		get_confirmation_to_show_message(true);
		return;
	}
	elseif ($data['remaining']<1 || $data['expiry']<time())
	{
		// the remaining count is not needed... it's only about expiry
		echo "<p class=error>ERROR! The message is expired.</p>";
		return;
	}

	// So, it unbans the user even if there was no password to enter.
	// I think it should be fine, because there's a limited number of
	// messages that expire and their links are not known.
	// Therefore, it can't be used to reset the counter and
	// brute force.

	unban();

	if ($data['remaining']==1)
		echo
			"<p class='save-warning last_show'>"
			."This is the last time this message is shown! Save it in a secure place if you need it."
			."</p>";
	else
		echo
			"<p class='save-warning notlast'>"
			."This message is available temporarily. Save it in a secure place if you need it."
			."</p>";

	echo "<textarea readonly>$data[message]</textarea>";

	$data['remaining']--;
	$data['has_passphrase'] = ( ($_POST['passphrase'] ?? '') != '' );
	save_message_file($data);
}



function get_confirmation_to_show_message($failed = false) // --------------------------------
{
	$filename = $_SERVER['DOCUMENT_ROOT'].'/message-'.$_SERVER['QUERY_STRING'].'.php';
	$data = get_message_data($filename,'', true);

	if ($data === 'no_message')
	{
		echo "<p class=error>There's no such message or it has expired!</p>";
		return;
	}

	if ($failed)
		echo "<p class=error>ERROR! Incorrect passphrase.</p>";

	echo
		"<p>This message is available for "
		.$data['remaining']
		." more views, until "
		.date('y-m-d H:i',$data['expiry'])
		.".</p>"
		."<form method=POST id=show-message>"
		."<input type=hidden name=page value=show >"
		."<input type=hidden name=message value=$_SERVER[QUERY_STRING]>"
	;

	if ($data['has_passphrase']=='NO')
		echo
			"<p>Are you sure you want to view the message?</p>"
			."<input type=submit value=Show autofocus>"
		;
	else
		echo
			"<label>Passphrase: "
			."<input type=password name=passphrase required autofocus>"
			."</label><br>"
			."<input type=submit value=Show >"
		;

	echo "</form>"
	;
}



function get_message_data($filename, $passphrase, $simple = false) // ------------------------
{
	if (!file_exists($filename))
		return 'no_message';

	$message_lines = file($filename);
	$data = [];
	$data['filename'] = $filename;
	$data['custom_passphrase'] = $passphrase;

	foreach ($message_lines as $line)
	{
		if (trim($line) === '')
			continue;
		$elements = explode(':', $line);
		$data[ trim($elements[0] ?? 'NA') ] = trim($elements[1] ?? 'NA');
	}

	if ($data['expiry'] < time())
	{
		unlink($filename);
		return 'no_message';
	}

	if ($simple)
		return $data;

	$passphrase = trim($passphrase);
	$passphrase = ($passphrase == '' ? default_passphrase : $passphrase);

	$data['message'] =
		openssl_decrypt
		(
			($data['message'] ?? '')
			,'aes-256-ofb'
			,$passphrase
			,0
			,substr($filename.$_SERVER['SERVER_NAME'],0,16)
		)
	;

	if (substr($data['message'],0,9) != 'encrypted')
		return 'wrong_passphrase';
	else
		$data['message'] = substr($data['message'],9);

	return $data;
}



function set_master_password() // ------------------------------------------------------------
{
	echo
		<<<html
			<p>Welcome!</p>
			<p>This is probably your first time using the application 
			because there's no master password. Let's set it now.</p>
			<form method=POST>
			<input type=hidden name=task value=set_password>
			<label>
				Password:
				<input type=password name=password required autofocus>
				<br>
			</label>
			<label>
				Repeat password:
				<input type=password name=password2 required>
				<br>
			</label>
			<input type=submit value=Save>
		html
	;
}



function save_submitted_master_password() // -------------------------------------------------
{
	global $password_file;
	global $application_path;

	if (($_POST['password'] ?? '') == '' || ($_POST['password2'] ?? '') == '')
	{
		echo "<p class=error>No password entered!</p>";
		return;
	}

	if ($_POST['password'] != $_POST['password2'])
	{
		echo "<p class=error>The passwords you've entered do not match.</p>";
		echo "<a href=/>Try again</a>";
		return;
	}

	$result =
		file_put_contents
		(
			$password_file
			,password_hash($_POST['password'], PASSWORD_BCRYPT )
		)
	;

	chmod($password_file,0600);

	if ($result===false)
		echo
			<<<html
				<p class=error>Couldn't save the config file!</p>
				<p>
					There may be an issue with permissions;
					make sure www-data has write access to the application directory
					by running the following commands on your server:
				</p>
				<code>
					chown www-data {$application_path}
					chmod 770      {$application_path}
				</code>
			html
		;
	else
		echo
			<<<html
				<p>Your password is saved and you can use the application now.</p>
				<p>
					To change the password later, delete the file:<br>
					{$password_file}
				</p>
				<a href=/>Create a message</a>
			html
		;
}



function clean_up_expired_messages() // ------------------------------------------------------
{
	$items = scandir('.');
	echo "<div id=cleanup>Existing messages: ";

	foreach ($items as $item)
		if (substr($item,0,7) === 'message')
		{
			$lines = file($item);
			$expired = false;
			foreach ($lines as $line)
			{
				$line = trim($line);
				if ($line==='')
					continue;
				$elements = explode(':',$line);
				if (trim($elements[0])=='expiry')
				{
					$expired = time() > (int)($elements[1]);
					break;
				}
			}
			echo ($expired ? 'X ' : 'O ');
			if ($expired)
				unlink($item);
		}

	echo "</div>";
}



function ip_filename() // --------------------------------------------------------------------
{
	// converting the IP address into a string suitable to be used as file name
	return str_replace([':','.'], ['-','-'], $_SERVER['REMOTE_ADDR']);
}



function is_banned() // ----------------------------------------------------------------------
{
	global $failed_attempts;
	$ip_filename = ip_filename();

	// if there's no IP file, the IP is not banned

	if (!file_exists('ip-'.$ip_filename))
		return false;

	// banned: there's the timestamp for when the ban is lifted
	// not banned: the number of failed attempts is written in the file

	$file_content = file_get_contents('ip-'.$ip_filename);
	if (strlen($file_content) < 6) // <6 wouldn't be a timestamp
	{
		$failed_attempts = $file_content;
		return false;
	}
	elseif ($file_content > time())
		return true;
}



function log_failed_attempt() // -------------------------------------------------------------
{
	global $failed_attempts;
	$ip_filename = ip_filename();
	$failed_attempts++;

	// banned: the timestamp for ending the ban will be recorded
	// not banned: the updated number of failed attempts is recorded

	if ($failed_attempts >= failed_attempts_to_ban)
		file_put_contents('ip-'.$ip_filename, strtotime('now +'.ban_hours.' hours'));
	else
		file_put_contents('ip-'.$ip_filename, $failed_attempts);
}



function unban() // --------------------------------------------------------------------------
{
	global $failed_attempts;
	$ip_filename = ip_filename();

	if (file_exists('ip-'.$ip_filename))
		unlink('ip-'.$ip_filename);
} 


