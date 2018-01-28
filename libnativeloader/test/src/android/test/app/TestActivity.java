/*
 * Copyright (C) 2018 The Android Open Source Project
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

package android.test.app;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class TestActivity extends Activity {

    @Override
    public void onCreate(Bundle icicle) {
         super.onCreate(icicle);
         tryLoadingLib("foo.oem1");
         tryLoadingLib("bar.oem1");
         tryLoadingLib("foo.oem2");
         tryLoadingLib("bar.oem2");
    }

    private void tryLoadingLib(String name) {
        try {
            System.loadLibrary(name);
            Log.d(getPackageName(), "library " + name + " is successfully loaded");
        } catch (UnsatisfiedLinkError e) {
            Log.d(getPackageName(), "failed to load libarary " + name, e);
        }
    }
}
