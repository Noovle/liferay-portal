/**
 * Copyright (c) 2000-present Liferay, Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 */

package com.liferay.portal.fabric.netty.rpc;

import com.liferay.portal.fabric.netty.NettyTestUtil;
import com.liferay.portal.kernel.test.CodeCoverageAssertor;

import io.netty.channel.embedded.EmbeddedChannel;

import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

/**
 * @author Shuyang Zhou
 */
public class ChannelThreadLocalTest {

	@ClassRule
	public static CodeCoverageAssertor codeCoverageAssertor =
		new CodeCoverageAssertor();

	@Test
	public void testConstructor() {
		new ChannelThreadLocal();
	}

	@Test
	public void testGetChannel() {
		try {
			ChannelThreadLocal.getChannel();
		}
		catch (IllegalStateException ise) {
			Assert.assertEquals("Channel is null", ise.getMessage());
		}

		EmbeddedChannel embeddedChannel =
			NettyTestUtil.createEmptyEmbeddedChannel();

		ChannelThreadLocal.setChannel(embeddedChannel);

		Assert.assertSame(embeddedChannel, ChannelThreadLocal.getChannel());

		ChannelThreadLocal.removeChannel();

		try {
			ChannelThreadLocal.getChannel();
		}
		catch (IllegalStateException ise) {
			Assert.assertEquals("Channel is null", ise.getMessage());
		}
	}

}