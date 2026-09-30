package app.void

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder

/**
 * Keeps a call's microphone working while the screen is locked or the user is
 * in another app, as a phone call does.
 *
 * Android silences the microphone for an app in the background unless it runs
 * a foreground service of type `microphone`, which must show a notification.
 * This service does nothing else: it exists only while a call's audio is
 * running, and its notification says a call is in progress and nothing more —
 * not who it is with.
 */
class CallService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL, "Calls", NotificationManager.IMPORTANCE_LOW).apply {
                description = "Shown while a call is in progress."
            },
        )
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = Notification.Builder(this, CHANNEL)
            .setContentTitle("Call in progress")
            .setSmallIcon(android.R.drawable.stat_sys_phone_call)
            .setContentIntent(open)
            .setOngoing(true)
            // FR-STOR-06's spirit: nothing about the call on a locked screen.
            .setVisibility(Notification.VISIBILITY_SECRET)
            .build()
        startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE)
        return START_NOT_STICKY
    }

    companion object {
        private const val CHANNEL = "void-calls"
        private const val NOTIFICATION_ID = 1

        fun start(context: Context) {
            runCatching { context.startForegroundService(Intent(context, CallService::class.java)) }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, CallService::class.java))
        }
    }
}
