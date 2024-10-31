package com.example.monitoring

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import com.bytedance.shadowhook.ShadowHook
import com.example.monitoring.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    fun initInlineHook() {
        ShadowHook.init(
            ShadowHook.ConfigBuilder()
                .setMode(ShadowHook.Mode.UNIQUE)
                .build()
        )
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        initInlineHook()
        doInlineHook()

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.sampleText.text = stringCos(5)
    }

    override fun onDestroy() {
        super.onDestroy()
        doInlineUnhook()
    }

    external fun stringCos(number: Int): String
    external fun doInlineHook()
    external fun doInlineUnhook()
    external fun tracking()

    companion object {
        init {
            System.loadLibrary("monitoring")
        }
    }
}