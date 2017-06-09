package Events;

/**
 * Created by abdullah on 09/06/2017.
 */
public class ErrorEvent {

    private String errorMessage;

    public ErrorEvent(String m) {
        this.errorMessage = m;
    }

    public String getErrorMessage() {
        return errorMessage;
    }
}
