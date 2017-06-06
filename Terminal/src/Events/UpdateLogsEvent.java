package Events;

/**
 * Created by abdullah on 06/06/2017.
 */
public class UpdateLogsEvent {

    private String log;

    public UpdateLogsEvent(String log) {
        this.log = log;
    }

    public String getLog() {
        return log;
    }
}
