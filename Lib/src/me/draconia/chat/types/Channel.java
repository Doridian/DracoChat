package me.draconia.chat.types;

import java.io.Serializable;

public abstract class Channel implements MessageContext, Serializable {
	public static final long serialVersionUID = -1L;

	public String name;

	protected Channel(String name) {
		this.name = name;
	}

	@Override
	public int hashCode() {
		return name.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null)
			return false;
		if (!(obj instanceof Channel))
			return false;
		return name.equals(((Channel) obj).name);
	}

	@Override
	public String toString() {
		return "C#" + name;
	}

	@Override
	public String getContextName() {
		return "#" + name;
	}
}
