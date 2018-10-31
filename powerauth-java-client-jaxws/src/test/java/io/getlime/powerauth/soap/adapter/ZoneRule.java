package io.getlime.powerauth.soap.adapter;

import java.time.ZoneId;
import java.util.TimeZone;

import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

public class ZoneRule extends TestWatcher {

    private TimeZone systemDefault;
    private final ZoneId zone;

    public ZoneRule(ZoneId zone) {
        this.zone = zone;
    }

    @Override
    protected void starting(Description description) {
        systemDefault = TimeZone.getDefault();
        super.starting(description);

        TimeZone.setDefault(TimeZone.getTimeZone(zone));
    }

    @Override
    protected void finished(Description description) {
        super.finished(description);
        TimeZone.setDefault(systemDefault);
    }
}