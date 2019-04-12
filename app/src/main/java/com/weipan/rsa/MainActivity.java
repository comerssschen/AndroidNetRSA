package com.weipan.rsa;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.security.PrivateKey;
import java.security.PublicKey;

import Decoder.BASE64Decoder;
import Decoder.BASE64Encoder;

/**
 * @author chenchao
 * @date 2016年10月22日 下午1:40:23
 */

public class MainActivity extends AppCompatActivity implements OnClickListener {

	private EditText edit;
	private Button button01;
	private Button button02;
	private TextView mText01;
	private TextView mText02;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private String result;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		String pubKeyXml3 = "<RSAKeyValue><Modulus>xG1aPBJdKFGwxbLAa91w8bMg+PaJmP63FECaUuA7L8f361BldgRZXbLvi6IaVHra7rEy/Wfk86f+9oiypAWtdc7SlZS7oocSbIPH30Clbv4qMhPtDegf0yWXuh5ISqrhFE0rbT5frJsU7UfYr4RMw0zSxTQEmbbW1lUg9lmI9Cs=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
		String priKeyXml3 = "<RSAKeyValue><Modulus>xG1aPBJdKFGwxbLAa91w8bMg+PaJmP63FECaUuA7L8f361BldgRZXbLvi6IaVHra7rEy/Wfk86f+9oiypAWtdc7SlZS7oocSbIPH30Clbv4qMhPtDegf0yWXuh5ISqrhFE0rbT5frJsU7UfYr4RMw0zSxTQEmbbW1lUg9lmI9Cs=</Modulus><Exponent>AQAB</Exponent><P>9zsvxgmUMQSaJNZwjWiOUiX+8K+NgZ1dLX1wMsxD9wio4GPJXS1jBpt645R8pi1Vj5yT2pEy6Tq6raGVApvpCw==</P><Q>y2Tf5rfrOMF1NOywKRX8TLyKPka9t6QwMl2z+jAqAlIzA5bQ7BTm8mq4YOuQlz4Ti0uNybIHGYFz+us5d19VYQ==</Q><DP>BjtjtOZA6gtnp04QgEAGdmOmzYJfWskQtDjZPy6O+Acr2pwpU0P1nxEERABWNAoogfo8b+IBGof0dLQCAZLUiQ==</DP><DQ>VfH5Prfm2GO/EC8XvTTCGPbuf6RK1Ie3qgC4ZXbmuXZcgh6/h5LJiBQadzHzNkWP4qN5dYoZv+hYxuWQseWB4Q==</DQ><InverseQ>HK06vP+pvkVF9GpbnWLcUlEs8tA5FeMzQT9jdKWwt13T9IuPZ6G10nSAZRwwSuy4b224Unx9Egh+RnrZSngr/g==</InverseQ><D>uGiNWW5IJS0kT0Z03g9kFJX+M52JKqifipToDTxUdJRAzZuJ1ZVZrNzrhWTnYT6Bwat8WmkqihHDDQLi65gk8pjs6cgSjtrXsXNcRuH+h1JoPUjP3ZA8PrbYSNDjTssfXmBrJPJX5xyLxNiVYqw2ru3EAlBY1BeLGrWr1g9LxEE=</D></RSAKeyValue>";

		publicKey = RsaHelper.decodePublicKeyFromXml(pubKeyXml3);
		privateKey = RsaHelper.decodePrivateKeyFromXml(priKeyXml3);
		initView();
	}

	private void initView() {
		edit = (EditText) findViewById(R.id.edit_01);
		button01 = (Button) findViewById(R.id.button_01);
		button02 = (Button) findViewById(R.id.button_02);
		mText01 = (TextView) findViewById(R.id.text_01);
		mText02 = (TextView) findViewById(R.id.text_02);

		button01.setOnClickListener(this);
		button02.setOnClickListener(this);
	}


//	解密
	private String decryptData(String data) {
		try {
			// 因为RSA加密后的内容经Base64再加密转换了一下，所以先Base64解密回来再给RSA解密
			BASE64Decoder decoder = new BASE64Decoder();
			byte[] b1 = decoder.decodeBuffer(data);
			byte[] decryptByte = RSAUtils.decryptData(b1, privateKey);
			String decryptStr = new String(decryptByte);
			return decryptStr;
		} catch (Exception e) {
			e.printStackTrace();
			return "解密错误";
		}
	}

	private String cryptData(String data) {
		String source = data;
		try {
			// 加密
			byte[] encryptByte = RSAUtils.encryptData(source.getBytes("UTF-8"), publicKey);
			// 为了方便观察吧加密后的数据用base64加密转一下，要不然看起来是乱码,所以解密是也是要用Base64先转换
			BASE64Encoder encoder = new BASE64Encoder();
			String ss = encoder.encode(encryptByte);
			Log.e("huangyf", ss);
			return ss;
		} catch (Exception e) {
			e.printStackTrace();
			return "加密错误";
		}
	}

	@Override
	public void onClick(View view) {
		if (view == button01) {
			String data = edit.getText().toString();
			if (TextUtils.isEmpty(data)) {
				Toast.makeText(this, "请输入内容", Toast.LENGTH_LONG).show();
			} else {
				result = cryptData(data);
				mText01.setText(result);
			}
		} else if (view == button02) {
//			String data = mText01.getText().toString();
			String data = "sy/om/R0bmH/61Vcj6/5Tqi+jzPLq2RLmaaq2MqLMKN4x7TRQNmYo8gmJOZLCQ0WVuoYVp3YtU19MyinfpzIaCtTdNXdDBAJ0zSclqmvTAvqa7Gmwlp1MIs5U2cXZLAHmWnyYt3JJJFNunWmQwrkGd3dO7MaGFvwJc3BZcYL3tc=";
			if (TextUtils.isEmpty(result)) {
				Toast.makeText(this, "解密内容不能为空", Toast.LENGTH_LONG).show();
			} else {
				mText02.setText(decryptData(result));
			}
		}

	}

	// private String test02() throws Exception {
	// String source = "455c92be281c2a42d722a8777726fc2b@1478746865348";
	// PublicKey publicKey = null;
	// try {
	// publicKey = RSAUtils.loadPublicKey(RSAUtils.PUCLIC_KEY);
	// } catch (Exception e) {
	// // TODO Auto-generated catch block
	// e.printStackTrace();
	// }
	//
	// /** 得到Cipher对象来实现对源数据的RSA加密 */
	// Cipher cipher = Cipher.getInstance("RSA");
	// cipher.init(Cipher.ENCRYPT_MODE, publicKey);
	// byte[] b = source.getBytes("UTF-8");
	// /** 执行加密操作 */
	// byte[] b1 = cipher.doFinal(b);
	// BASE64Encoder encoder = new BASE64Encoder();
	// String s = encoder.encode(b1);
	// System.out.println("用私钥解密后的字符串为05：" + s);
	// Log.i("huangyf",s);
	// return s;
	// }
	//
}
