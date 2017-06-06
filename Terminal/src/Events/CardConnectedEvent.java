package Events;

/**
 * Created by abdullah on 06/06/2017.
 */
public class CardConnectedEvent {

    private String cardName;

    public CardConnectedEvent(String cardName) {
        this.cardName = cardName;
    }

    public String getCardName() {
        return cardName;
    }
}
