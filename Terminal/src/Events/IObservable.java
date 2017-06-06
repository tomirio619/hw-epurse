package Events;

import java.util.Observer;

/**
 * Created by abdullah on 06/06/2017.
 */
public interface IObservable {

    public void addObserver(Observer o);
    public void update(Object event);


}
