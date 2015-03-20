/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.activity.safedroid;

import com.example.safedroid.R;

import com.service.safedroid.AppRequestService;

import android.support.v7.app.ActionBarActivity;
import android.annotation.TargetApi;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

public class MainActivity extends ActionBarActivity {

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		final Button toggleServiceButton = (Button) findViewById(R.id.button1);
		final Context context = getApplicationContext();
		toggleServiceButton.setOnClickListener(new View.OnClickListener() {
			@TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
			public void onClick(View v) {
				
				Intent intent = VpnService.prepare(getApplicationContext());
				
				if (toggleServiceButton.getText().equals("Start")) {
					toggleServiceButton.setText("Stop");	
					if (intent != null) {
						startActivityForResult(intent, 0);
						context.startService(intent);
						
						
					} else {
						onActivityResult(0, RESULT_OK, null);
					}
					

				} else {
					toggleServiceButton.setText("Start");

					context.stopService(intent);

					CharSequence text = "SafeDroid Service Stopped!";
					int duration = Toast.LENGTH_SHORT;
					Toast toast = Toast.makeText(context, text, duration);
					toast.show();
				}

			}
		});
	}
	
	protected void onActivityResult(int requestCode, int resultCode, Intent data) {
		  if (resultCode == RESULT_OK) {
		  	Intent intent = new Intent(this, AppRequestService.class);
		  	startService(intent);
		  }
		}
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		int id = item.getItemId();
		if (id == R.id.action_settings) {
			return true;
		}
		return super.onOptionsItemSelected(item);
	}
}
