/*
 * kirkwood-fbxgw2r.c
 *
 * Modified-from: kirkwood-rd88f6282a.c, which was before
 * Modified-from: kirkwood-openrd.c
 * Which is:
 * (c) 2010 Arnaud Patard <apatard@mandriva.com>
 * (c) 2010 Arnaud Patard <arnaud.patard@rtp-net.org>
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the  License, or (at your
 *  option) any later version.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <sound/soc.h>
#include <asm/mach-types.h>
#include "../codecs/cs42l52.h"

#if 0
static void dump_registers(struct snd_soc_codec *codec)
{
	int i;

	for (i = 0; i < 0x40; ++i) {
		int val = snd_soc_read(codec, i);
		if (val < 0)
			printk("%02x: <unreadable (you're drunk)>\n", i);
		else
			printk("%02x: %02x\n", i, val);
	}
}
#endif

static int fbxgw2r_dai_init(struct snd_soc_pcm_runtime *rtd)
{
	struct snd_soc_codec *codec = rtd->codec;
	u8 reg;

#if 0
	printk("Default register configuration:\n");
	dump_registers(codec);
#endif

	/*
	 * make sure we correctly transition from speaker to headphone
	 * and vice&versa.
	 */
	snd_soc_write(codec, 0x4, 0x05);

	/*
	 * select input4a/input4b for capture
	 */
	reg = snd_soc_read(codec, 0x8);
	reg &= ~(7 << 5);
	reg |= (3 << 5);
	snd_soc_write(codec, 0x8, reg);

	reg = snd_soc_read(codec, 0x9);
	reg &= ~(7 << 5);
	reg |= (3 << 5);
	snd_soc_write(codec, 0x9, reg);

	/*
	 * set headphone analog gain to 1.000
	 */
	reg = snd_soc_read(codec, 0x0d);
	reg &= ~0xe0;
	reg |= 0xc0;
	snd_soc_write(codec, 0x0d, reg);

	return 0;
}

static int fbxgw2r_hw_params(struct snd_pcm_substream *substream,
		struct snd_pcm_hw_params *params)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct snd_soc_dai *cpu_dai = rtd->cpu_dai;
	struct snd_soc_dai *codec_dai = rtd->codec_dai;
	int ret;
	unsigned int fmt;
	int freq = 0;

	fmt = SND_SOC_DAIFMT_I2S | SND_SOC_DAIFMT_CBS_CFS;
	ret = snd_soc_dai_set_fmt(cpu_dai, fmt);
	if (ret < 0)
		return ret;
	ret = snd_soc_dai_set_fmt(codec_dai, fmt);
	if (ret < 0)
		return ret;


	switch (params_rate(params)) {
	default:
	case 44100:
		freq = 11289600;
		break;
	case 96000:
	case 48000:
		freq = 12288000;
		break;
	}

	return snd_soc_dai_set_sysclk(codec_dai, 0, freq, SND_SOC_CLOCK_IN);
}

static int fbxgw2r_startup(struct snd_pcm_substream *substream)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct snd_soc_codec *codec = rtd->codec_dai->codec;

	if (substream->stream == SNDRV_PCM_STREAM_CAPTURE) {
		u8 reg;

		/*
		 * power up ADC A & B
		 */
		reg = snd_soc_read(codec, 0x2);
		reg &= ~(3 << 1);
		snd_soc_write(codec, 0x2, reg);

		/*
		 * unmute ADC A mixer volume
		 */
		reg = snd_soc_read(codec, 0x18);
		reg &= ~(1 << 7);
		snd_soc_write(codec, 0x18, reg);

		/*
		 * unmute ADC B mixer volume
		 */
		reg = snd_soc_read(codec, 0x19);
		reg &= ~(1 << 7);
		snd_soc_write(codec, 0x19, reg);
	}

#if 0
	dump_registers(codec);
#endif
	return 0;
}

static void fbxgw2r_shutdown(struct snd_pcm_substream *substream)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct snd_soc_codec *codec = rtd->codec_dai->codec;

	if (substream->stream == SNDRV_PCM_STREAM_CAPTURE) {
		u8 reg;

		/*
		 * power down ADC A & B
		 */
		reg = snd_soc_read(codec, 0x2);
		reg |= (3 << 1);
		snd_soc_write(codec, 0x2, reg);

		/*
		 * mute ADC A mixer volume
		 */
		reg = snd_soc_read(codec, 0x18);
		reg |= (1 << 7);
		snd_soc_write(codec, 0x18, reg);

		/*
		 * mute ADC B mixer volume
		 */
		reg = snd_soc_read(codec, 0x19);
		reg |= (1 << 7);
		snd_soc_write(codec, 0x19, reg);
	}
}

static struct snd_soc_ops fbxgw2r_ops = {
	.hw_params = fbxgw2r_hw_params,
	.startup = fbxgw2r_startup,
	.shutdown = fbxgw2r_shutdown,
};

static struct snd_soc_dai_link fbxgw2r_dai[] = {
	{
		.name = "CS42L52",
		.stream_name = "CS42L52 HiFi",
		.cpu_name = "mvebu-audio",
		.cpu_dai_name = "i2s",
		.platform_name = "mvebu-audio",
		.codec_dai_name = "cs42l52",
		.codec_name = "cs42l52.1-004a",
		.ops = &fbxgw2r_ops,
		.init = fbxgw2r_dai_init,
	},
};


static struct snd_soc_card fbxgw2r = {
	.name = "FBXGW2R",
	.dai_link = fbxgw2r_dai,
	.num_links = ARRAY_SIZE(fbxgw2r_dai),
};

static int fbxgw2r_probe(struct platform_device *pdev)
{
	struct snd_soc_card *card = &fbxgw2r;

	card->dev = &pdev->dev;
	return snd_soc_register_card(card);
}

static int fbxgw2r_remove(struct platform_device *pdev)
{
	struct snd_soc_card *card = platform_get_drvdata(pdev);

	return snd_soc_unregister_card(card);
}

struct platform_driver fbxgw2r_driver = {
	.driver = {
		.name = "fbxgw2r-audio",
		.owner = THIS_MODULE,
	},
	.probe = fbxgw2r_probe,
	.remove = fbxgw2r_remove,
};

static int __init fbxgw2r_init(void)
{
	return platform_driver_register(&fbxgw2r_driver);
}

static void __exit fbxgw2r_exit(void)
{
	platform_driver_unregister(&fbxgw2r_driver);
}

module_init(fbxgw2r_init);
module_exit(fbxgw2r_exit);

/* Module information */
MODULE_DESCRIPTION("ALSA SoC FBXGW2R Client");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:soc-audio");
