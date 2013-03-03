package me.draconia.chat.types;

public class GenericContext implements MessageContext {
	public static final GenericContext instance = new GenericContext();

	@Override
	public String getContextName() {
		return "System";
	}

	private GenericContext() {
	}
}
