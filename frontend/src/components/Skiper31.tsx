"use client";

import { motion, useScroll, useTransform } from "framer-motion";
import { ReactLenis } from "lenis/react";
import { useRef } from "react";

import { cn } from "../lib/utils";

type CharacterProps = {
  char: string;
  index: number;
  centerIndex: number;
  scrollYProgress: any;
};

const CharacterV1 = ({
  char,
  index,
  centerIndex,
  scrollYProgress,
}: CharacterProps) => {
  const isSpace = char === " ";

  const distanceFromCenter = index - centerIndex;

  const x = useTransform(
    scrollYProgress,
    [0, 0.5],
    [distanceFromCenter * 50, 0],
  );
  const rotateX = useTransform(
    scrollYProgress,
    [0, 0.5],
    [distanceFromCenter * 50, 0],
  );

  return (
    <motion.span
      className={cn("inline-block", isSpace && "w-4")}
      style={{
        x,
        rotateX,
      }}
    >
      {char === " " ? "\u00A0" : char}
    </motion.span>
  );
};

const Skiper31 = ({ text }: { text: string }) => {
  const targetRef = useRef<HTMLDivElement | null>(null);

  const { scrollYProgress } = useScroll({
    target: targetRef,
  });

  const characters = text.split("");
  const centerIndex = Math.floor(characters.length / 2);

  return (
    <ReactLenis root>
      <main className="w-full bg-background text-foreground">
        <div
          ref={targetRef}
          className="relative box-border flex h-[100vh] items-center justify-center gap-[2vw] overflow-hidden p-[2vw]"
        >
          <div
            className="w-full max-w-4xl text-center text-4xl font-bold uppercase tracking-tighter"
            style={{
              perspective: "500px",
            }}
          >
            {characters.map((char, index) => (
              <CharacterV1
                key={index}
                char={char}
                index={index}
                centerIndex={centerIndex}
                scrollYProgress={scrollYProgress}
              />
            ))}
          </div>
        </div>
      </main>
    </ReactLenis>
  );
};

export { CharacterV1, Skiper31 };
